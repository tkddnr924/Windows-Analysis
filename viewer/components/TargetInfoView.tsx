"use client";
import { lookupEventCatalog } from "@/lib/eventCatalog";
import EventNoteOutlinedIcon from "@mui/icons-material/EventNoteOutlined";
import { ViewHeader } from "@/components/FilterControls";

import { useContext, useEffect, useMemo, useRef, useState } from "react";
import ArrowBackOutlinedIcon from "@mui/icons-material/ArrowBackOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import ChevronRightOutlinedIcon from "@mui/icons-material/ChevronRightOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import Tooltip from "@mui/material/Tooltip";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import ManageAccountsOutlinedIcon from "@mui/icons-material/ManageAccountsOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import SettingsOutlinedIcon from "@mui/icons-material/SettingsOutlined";
import WarningAmberOutlinedIcon from "@mui/icons-material/WarningAmberOutlined";
import WifiOutlinedIcon from "@mui/icons-material/WifiOutlined";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import AddOutlinedIcon from "@mui/icons-material/AddOutlined";
import DeleteOutlineOutlinedIcon from "@mui/icons-material/DeleteOutlineOutlined";
import { acbFlagNames, yesNo } from "@/lib/accountFields";
import type { AccountEventPage, AccountEventQuery, CsvData, DBRow, HostMetadata } from "@/lib/types";
import type { FetchLinkedRows } from "@/lib/types";
import { RecordScopeContext } from "@/lib/recordScope";
import { hostDirOfResultPath } from "@/lib/resultTables";
import { toBound, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import type { AccountDirectory } from "@/lib/accountIdentity";
import PaginationControls from "@/components/PaginationControls";
import { expandAccountPath } from "@/lib/accountPath";

interface TargetInfoViewProps {
  data: CsvData;
  /** Page this account's stored activity (TargetAccountEvents, matched at
   * parse time by role SID/name). Enables the account detail page. */
  loadAccountEvents?: (query: AccountEventQuery) => Promise<AccountEventPage>;
  /** Global incident period selected in the sidebar. */
  timeRange: TimeRange;
  /** Threaded so the account-event detail uses the same shared EventLog detail
   * panel (RowDetailPanel) as every other view. */
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** Bookmark state of the source record a row (optionally one timestamp
   *  field) points at. */
  isRowBookmarked?: (row: Row, field?: string) => boolean;
  isRecordBookmarked?: (row: Row) => boolean;
  onToggleBookmark?: (rowid: number, field: string) => void;
  accountDirectory?: AccountDirectory;
  /** docs-21: analyst-added host addresses; callbacks return an error or null. */
  analystAddresses?: string[];
  onAddAnalystAddress?: (address: string) => Promise<string | null>;
  onRemoveAnalystAddress?: (address: string) => Promise<string | null>;
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
  SystemRoot: "Windows 디렉터리",
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
  /** The TargetInfo row this entry came from; carries its source coordinates. */
  row: Row;
  rowid: number;
  sid: string;
  path: string;
  rawPath: string;
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


/**
 * 계정·네트워크 속성은 Metadata.sqlite(공통 참조 정보)에서 온다 — TargetInfo
 * 행은 표시값과 metadata_id 참조만 들고 있다(docs-01 #16). 계정명이 확인되지
 * 않으면(NULL) 이름을 지어내지 않고 화면이 SID를 표시한다.
 */
function buildAccount(r: Row, meta?: DBRow, groups?: string): Account {
  const sid = meta?.account_sid || r.name || "";
  const ridMatch = sid.match(/-(\d+)$/);
  const ridNum = ridMatch ? Number(ridMatch[1]) : NaN;
  // S-1-5-21-… is a machine/domain-issued account; RID 500 is the built-in
  // Administrator, RID ≥ 1000 are created users. Everything else (S-1-5-18/19/20)
  // is a service identity.
  const isUser = /^S-1-5-21-/.test(sid) && (ridNum === 500 || ridNum >= 1000);
  const profilePath = meta?.profile_path_resolved || meta?.profile_path || r.value || "";
  return {
    row: r,
    rowid: Number((r as unknown as Record<string, unknown>).__rowid),
    sid,
    path: profilePath,
    rawPath: meta?.profile_path || r.value || "",
    username: meta?.account_name || meta?.value || "",
    isUser,
    fullName: meta?.full_name || "",
    rid: meta?.rid || (Number.isFinite(ridNum) ? String(ridNum) : ""),
    ridSam: meta?.rid_sam || "",
    homeDir: meta?.home_directory || profilePath,
    created: meta?.created || "",
    lastLogin: meta?.last_login || "",
    passwordLastSet: meta?.password_last_set || "",
    lastFailedLogin: meta?.last_failed_login || "",
    loginCount: meta?.login_count || "",
    failedLoginCount: meta?.failed_login_count || "",
    // metadata stores disabled/special_account as 0/1 (NULL = unknown).
    disabled: yesNo(meta?.disabled),
    specialAccount: yesNo(meta?.special_account),
    groups: groups || "",
    // account_flags is the raw ACB hex; flag names live in details_json.acb_flags.
    accountFlags: acbFlagNames(meta?.details_json) || meta?.account_flags || "",
    sourceArtifact: meta?.name_source || "",
  };
}

function DetailSurface({ title, count, trailing, children }: { title: string; count?: number; trailing?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
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

// Fields the account detail can bookmark (see AccountDetailPage time rows).

export default function TargetInfoView({ data, loadAccountEvents, timeRange, onNavigate, onFetchLinkedRows, isRowBookmarked, isRecordBookmarked, onToggleBookmark, accountDirectory, analystAddresses = [], onAddAnalystAddress, onRemoveAnalystAddress }: TargetInfoViewProps) {
  // 북마크는 원본 레코드에 붙으므로 행이 실어 온 원본 좌표로 맞춘다.
  // Account bookmarks are field bookmarks; any of them marks the row.
  const bmRowids = useMemo(
    () => new Set((data.rows as Row[])
      .filter((row) => isRecordBookmarked?.(row))
      .map((row) => Number((row as Record<string, unknown>).__rowid))),
    [data.rows, isRecordBookmarked],
  );
  const [selectedAccount, setSelectedAccount] = useState<Account | null>(null);
  // 좌측 범주 내비게이션(25%)에서 고른 섹션을 우측(75%)에 표시한다.
  const [section, setSection] = useState<"accounts" | "system" | "interfaces" | "networks" | "hosts">("accounts");
  // 시스템 값 카드 클릭 → 즉시 복사, 잠깐 "복사됨" 표시.
  const [copied, setCopied] = useState<{ key: string; failed: boolean } | null>(null);
  const [selectedInterface, setSelectedInterface] = useState<NetInterface | null>(null);
  const [selectedNetwork, setSelectedNetwork] = useState<NetworkProfile | null>(null);
  // A replaced result drops selections that point at old rows.
  const [selectionData, setSelectionData] = useState(data);
  if (selectionData !== data) {
    setSelectionData(data);
    setSelectedAccount(null);
    setSelectedInterface(null);
    setSelectedNetwork(null);
  }
  const [newAddress, setNewAddress] = useState("");
  const [addressError, setAddressError] = useState<string | null>(null);
  const submitAddress = async () => {
    if (!onAddAnalystAddress || !newAddress.trim()) return;
    const error = await onAddAnalystAddress(newAddress.trim());
    setAddressError(error);
    if (!error) setNewAddress("");
  };
  // 호스트 공통 참조 정보(Metadata.sqlite) — 계정·네트워크 상세 속성의 출처다.
  // 열려 있는 결과 파일 경로에서 호스트 폴더를 얻는다.
  const scope = useContext(RecordScopeContext);
  const hostDir = scope ? hostDirOfResultPath(scope.fullPath) : "";
  const [hostMeta, setHostMeta] = useState<HostMetadata | null>(null);
  const [hostMetaError, setHostMetaError] = useState<string | null>(null);
  useEffect(() => {
    setHostMeta(null);
    setHostMetaError(null);
    if (!hostDir) return;
    let alive = true;
    window.api.hostMetadata(hostDir)
      .then((meta) => { if (alive) setHostMeta(meta); })
      // 조회 실패를 "정보 없음"으로 보여 주면 없는 사실로 오인된다.
      .catch(() => { if (alive) setHostMetaError("호스트 공통 참조 정보(metadata)를 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [hostDir]);
  const metaIndex = useMemo(() => {
    const byId = new Map<string, DBRow>();
    for (const row of hostMeta?.rows ?? []) byId.set(row.metadata_id, row);
    const join = (rows: DBRow[] | undefined, key: string) => {
      const map = new Map<string, string[]>();
      for (const row of rows ?? []) {
        const value = row[key];
        if (!value) continue;
        const list = map.get(row.metadata_id);
        if (list) list.push(value); else map.set(row.metadata_id, [value]);
      }
      return map;
    };
    return {
      byId,
      addresses: join(hostMeta?.addresses, "address"),
      subnetMasks: join(hostMeta?.addresses, "subnet_mask"),
      gateways: join(hostMeta?.gateways, "address"),
      dnsServers: join(hostMeta?.dnsServers, "address"),
      groups: join(hostMeta?.groups, "group_name"),
    };
  }, [hostMeta]);
  const { system, users, services, networks, interfaces, hostsEntries, computerName } = useMemo(() => {
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
    // hosts 파일 수동 등록 항목 — 유효 엔트리가 없으면 섹션 자체를 숨긴다.
    const hostsEntries: { name: string; ip: string }[] = [];

    for (const r of dedup) {
      const cat = r.category;
      if (cat === "SystemInfo" || cat === "OS" || cat === "System") {
        // Prefer a non-empty value; some rows carry only a timestamp
        // (e.g. LastShutdownTime), which we surface as the value.
        const value = r.value || r.timestamp || "";
        const prev = system.get(r.name);
        if (!prev || (!prev.value && value)) system.set(r.name, { value, timestamp: r.timestamp });
      } else if (cat === "Account") {
        const meta = r.metadata_id ? metaIndex.byId.get(r.metadata_id) : undefined;
        accounts.push(buildAccount(r, meta, (metaIndex.groups.get(r.metadata_id) ?? []).join(", ")));
      } else if (cat === "Network") {
        const name = r.value || "";
        const existing = netMap.get(name);
        if (!existing || r.timestamp > existing.timestamp) {
          netMap.set(name, { row: r, name, timestamp: r.timestamp || "" });
        }
      } else if (cat === "HostsFile" && r.value) {
        hostsEntries.push({ name: r.name || "", ip: r.value });
      } else if (cat === "NetworkInterface" && r.value) {
        const key = `${r.value}|${r.name}`;
        if (!ifaceMap.has(key)) {
          // 주소·게이트웨이·DNS는 metadata의 자식 표에 있다(한 인터페이스가
          // 여러 주소를 가질 수 있다). 상세 서랍이 읽을 수 있게 합쳐 둔다.
          const metadataId = r.metadata_id || "";
          const meta = metadataId ? metaIndex.byId.get(metadataId) : undefined;
          const addresses = (metaIndex.addresses.get(metadataId) ?? []).join(", ");
          const gateways = (metaIndex.gateways.get(metadataId) ?? []).join(", ");
          const dnsServers = (metaIndex.dnsServers.get(metadataId) ?? []).join(", ");
          const subnetMasks = (metaIndex.subnetMasks.get(metadataId) ?? []).join(", ");
          ifaceMap.set(key, {
            row: {
              ...r,
              interface_id: meta?.interface_id ?? "",
              interface_name: meta?.interface_name ?? meta?.value ?? "",
              mac_address: meta?.mac_address ?? "",
              network_profile: meta?.network_profile ?? "",
              dhcp_enabled: meta?.dhcp_enabled ?? "",
              dhcp_server: meta?.dhcp_server ?? "",
              lease_obtained: meta?.lease_obtained ?? "",
              lease_terminates: meta?.lease_terminates ?? "",
              domain: meta?.domain ?? "",
              observed_at: meta?.observed_at ?? "",
              resolution_status: meta?.resolution_status ?? "",
              addresses,
              subnet_masks: subnetMasks,
              gateways,
              dns_servers: dnsServers,
            },
            guid: meta?.interface_id || r.name || "",
            ip: addresses || r.value || "",
            subnet: subnetMasks,
            gateway: gateways,
            dns: dnsServers,
            dhcpServer: meta?.dhcp_server ?? "",
            domain: meta?.domain ?? "",
            dhcp: meta?.dhcp_enabled ?? "",
            leaseObtained: meta?.lease_obtained ?? "",
            leaseTerminates: meta?.lease_terminates ?? "",
          });
        }
      }
    }

    const systemRoot = system.get("SystemRoot")?.value || "";
    for (const account of accounts) {
      account.path = expandAccountPath(account.path, systemRoot);
      account.homeDir = expandAccountPath(account.homeDir, systemRoot);
    }

    // Users first, then system accounts; each by creation time (oldest first),
    // accounts without one after them by name.
    const byCreated = (a: Account, b: Account) =>
      a.created && b.created ? a.created.localeCompare(b.created) || a.username.localeCompare(b.username)
        : a.created ? -1 : b.created ? 1 : a.username.localeCompare(b.username);
    const users = accounts.filter((a) => a.isUser).sort(byCreated);
    const services = accounts.filter((a) => !a.isUser).sort(byCreated);
    const networks = [...netMap.values()]
      .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const interfaces = [...ifaceMap.values()].sort((a, b) => a.ip.localeCompare(b.ip));

    const computerName = system.get("ComputerName")?.value || "알 수 없는 시스템";

    return { system, users, services, networks, interfaces, hostsEntries, computerName };
  }, [data.rows, metaIndex]);

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
    return <AccountDetailPage account={selectedAccount} onBack={() => setSelectedAccount(null)} loadEvents={loadAccountEvents} timeRange={timeRange} onNavigate={onNavigate} onFetchLinkedRows={onFetchLinkedRows} isRowBookmarked={isRowBookmarked} onToggleBookmark={onToggleBookmark} accountDirectory={accountDirectory} />;
  }

  const accounts = [...users, ...services];

  const sections = [
    { key: "accounts" as const, label: "계정 정보", icon: ManageAccountsOutlinedIcon },
    { key: "system" as const, label: "시스템", icon: DesktopWindowsOutlinedIcon },
    { key: "interfaces" as const, label: "네트워크 어댑터", icon: LanOutlinedIcon },
    { key: "networks" as const, label: "연결한 네트워크", icon: WifiOutlinedIcon },
    ...(hostsEntries.length > 0 ? [{ key: "hosts" as const, label: "호스트 파일 (hosts)", icon: DnsOutlinedIcon }] : []),
  ];

  return (
    <div className="dfir-view" style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg)" }}>
      <ViewHeader icon={InfoOutlinedIcon} title={<>호스트 정보 <span aria-hidden="true" style={{ color: "var(--text-faint)", padding: "0 2px" }}>|</span> {computerName}</>} />
      {hostMetaError && <div role="alert" style={{ padding: "6px 14px", color: "var(--danger)", fontSize: 12 }}>{hostMetaError}</div>}

      <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(170px, 15%) minmax(0, 1fr)", overflow: "hidden" }}>
        <nav aria-label="호스트 정보 범주" style={{ minHeight: 0, overflow: "auto", padding: 10, borderRight: "1px solid var(--border)" }}>
          <div style={{ padding: "4px 8px 8px", color: "var(--text-faint)", fontSize: 11.5, fontWeight: 700 }}>호스트 범주</div>
          {sections.map(({ key, label, icon: Icon }) => {
            const active = section === key;
            return (
              <button key={key} type="button" onClick={() => setSection(key)} className={active ? "nm-btn" : undefined} style={{ width: "100%", minHeight: 36, marginBottom: 2, padding: "0 10px", display: "flex", alignItems: "center", justifyContent: "flex-start", gap: 8, border: active ? "1px solid color-mix(in srgb, var(--accent) 45%, var(--border))" : "1px solid transparent", borderRadius: "var(--radius)", background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--text)" : "var(--text-dim)", cursor: "pointer", textAlign: "left" }}>
                <Icon sx={{ fontSize: 16, flexShrink: 0, color: active ? "var(--accent)" : "inherit" }} />
                <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: active ? 700 : 550 }}>{label}</span>
              </button>
            );
          })}
        </nav>

        <section style={{ minWidth: 0, minHeight: 0, overflow: "auto", overscrollBehavior: "contain", padding: 14 }}>
          {section === "accounts" && <AccountRegistry accounts={accounts} bookmarkedRowids={bmRowids} onSelect={setSelectedAccount} />}

          {section === "hosts" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 8, alignContent: "start" }}>
              {hostsEntries.map((entry, index) => (
                <div key={`${entry.ip}-${entry.name}-${index}`} style={{ display: "flex", alignItems: "center", gap: 12, minHeight: 62, padding: "10px 14px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)" }}>
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 14%, transparent)" }}>
                    <DnsOutlinedIcon sx={{ fontSize: 17, color: "var(--text-dim)" }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700 }} title={entry.name}>{entry.name || "이름 없음"}</span>
                    <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12, overflowWrap: "anywhere" }}>{entry.ip}</span>
                  </span>
                </div>
              ))}
            </div>
          )}

          {section === "system" && (
            orderedSystem.length === 0 ? (
              <div style={{ color: "var(--text-faint)", fontSize: 13 }}>시스템 정보가 없습니다.</div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 8, alignContent: "start" }}>
                {orderedSystem.map((k) => {
                  const value = system.get(k)?.value || "";
                  // 시각·빌드류 값은 모노스페이스로.
                  const mono = /Time|Date|Build/i.test(k) || /^\d{4}-\d{2}-\d{2}/.test(value);
                  const copyState = copied?.key === k ? copied : null;
                  return (
                    <button
                      key={k}
                      type="button"
                      title="클릭하면 값을 복사합니다"
                      aria-label={`${SYSTEM_LABELS[k] ?? k} 값 복사`}
                      onClick={() => {
                        if (!value) return;
                        const done = (failed: boolean) => {
                          setCopied({ key: k, failed });
                          setTimeout(() => setCopied((current) => (current?.key === k ? null : current)), failed ? 2400 : 1200);
                        };
                        if (!navigator.clipboard) { done(true); return; }
                        navigator.clipboard.writeText(value).then(() => done(false), () => done(true));
                      }}
                      style={{ border: `1px solid ${copyState ? `color-mix(in srgb, ${copyState.failed ? "var(--danger)" : "var(--success)"} 55%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", padding: "10px 14px", display: "flex", alignItems: "center", gap: 12, color: "inherit", cursor: value ? "pointer" : "default", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-panel)"; }}
                    >
                      <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 14%, transparent)" }}>
                        <DesktopWindowsOutlinedIcon sx={{ fontSize: 17, color: "var(--text-dim)" }} />
                      </span>
                      <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                        <span style={{ color: "var(--text-dim)", fontSize: 12 }}>{SYSTEM_LABELS[k] ?? k}</span>
                        <span style={{ color: value ? "var(--text)" : "var(--text-faint)", fontSize: 13.5, fontWeight: 700, fontFamily: mono ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{value || "정보 없음"}</span>
                      </span>
                      {copyState && <span role={copyState.failed ? "alert" : undefined} style={{ flexShrink: 0, color: copyState.failed ? "var(--danger)" : "var(--success)", fontSize: 11.5, fontWeight: 700 }}>{copyState.failed ? "복사 실패" : "복사됨"}</span>}
                    </button>
                  );
                })}
              </div>
            )
          )}

          {section === "interfaces" && (interfaces.length === 0 && !onAddAnalystAddress ? <div style={{ color: "var(--text-faint)", fontSize: 13 }}>IP 구성 정보가 없습니다.</div> : <>
            {interfaces.map((n) => {
              const active = selectedInterface?.guid === n.guid && selectedInterface?.ip === n.ip;
              const detailLine = [n.gateway && `게이트웨이 ${n.gateway}`, n.dns && `DNS ${n.dns}`, n.domain && `도메인 ${n.domain}`].filter(Boolean).join(" · ");
              return (
                <button
                  type="button"
                  key={`${n.ip}|${n.guid}`}
                  onClick={() => { setSelectedNetwork(null); setSelectedInterface(n); }}
                  aria-label={`${n.ip} 어댑터 상세 보기`}
                  style={{ borderRadius: "var(--radius)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 58, marginBottom: 8, padding: "9px 14px", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--bg-selected)" : "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = active ? "var(--bg-selected)" : "var(--bg-panel)"; }}
                >
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "var(--accent-subtle)" }}>
                    <LanOutlinedIcon sx={{ fontSize: 17, color: "var(--accent)" }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{n.ip}</span>
                    {detailLine && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{detailLine}</span>}
                  </span>
                  <ChevronRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />
                </button>
              );
            })}
            {analystAddresses.map((address) => (
              <div key={`analyst|${address}`} style={{ borderRadius: "var(--radius)", display: "flex", alignItems: "center", gap: 12, minHeight: 50, marginBottom: 8, padding: "7px 10px 7px 14px", border: "1px dashed var(--border)", background: "var(--bg-panel)" }}>
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 14%, transparent)" }}>
                  <LanOutlinedIcon sx={{ fontSize: 17, color: "var(--text-dim)" }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "baseline", gap: 8 }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{address}</span>
                  <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>분석가 추가</span>
                </span>
                {onRemoveAnalystAddress && <button type="button" onClick={() => { void onRemoveAnalystAddress(address).then(setAddressError); }} aria-label={`${address} 삭제`} title="삭제" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><DeleteOutlineOutlinedIcon sx={{ fontSize: 16 }} /></button>}
              </div>
            ))}
            {onAddAnalystAddress && (
              <form onSubmit={(event) => { event.preventDefault(); void submitAddress(); }} style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 50, padding: "7px 10px 7px 14px", border: "1px dashed var(--border)", borderRadius: "var(--radius)" }}>
                <AddOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />
                <input value={newAddress} onChange={(event) => { setNewAddress(event.target.value); setAddressError(null); }} placeholder="IP 추가" aria-label="추가할 IP" style={{ flex: 1, minWidth: 0, minHeight: 30, padding: "4px 8px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5 }} />
                <button type="submit" disabled={!newAddress.trim()} style={{ minHeight: 30, padding: "4px 12px", border: "1px solid var(--accent)", borderRadius: "var(--radius)", background: "var(--accent-subtle)", color: "var(--accent)", fontSize: 12, fontWeight: 700, cursor: newAddress.trim() ? "pointer" : "default", opacity: newAddress.trim() ? 1 : 0.55 }}>추가</button>
              </form>
            )}
            {addressError && <div role="alert" style={{ marginTop: 6, color: "var(--danger)", fontSize: 12 }}>{addressError}</div>}
          </>)}

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
                  style={{ borderRadius: "var(--radius)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 52, marginBottom: 8, padding: "8px 14px", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--bg-selected)" : "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = active ? "var(--bg-selected)" : "var(--bg-panel)"; }}
                >
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 14%, transparent)" }}>
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
  // Keep system accounts achromatic; blue identifies user accounts.
  const accountColor = account.isUser ? "var(--accent)" : "#d0d0d0";
  const tileColor = account.specialAccount.startsWith("예") ? "var(--warning)" : accountColor;
  return (
    <button
      type="button"
      onClick={onSelect}
      title="자세히 보기"
      aria-label={`${account.username || "이름 없는 계정"} 계정 상세 보기${bookmarked ? ", 북마크됨" : ""}`}
      className={bookmarked ? "dfir-bookmarked-row" : undefined}
      style={{ borderRadius: "var(--radius)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", color: "inherit", cursor: "pointer", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
      onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
      onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-panel)"; }}
    >
      <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${tileColor} 15%, transparent)` }}>
        {account.isUser ? <PersonOutlineIcon sx={{ fontSize: 17, color: tileColor }} /> : <SettingsOutlinedIcon sx={{ fontSize: 17, color: tileColor }} />}
      </span>
      <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
        <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
          <span title={account.username} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700, color: "var(--text)" }}>{account.username || "(이름 없음)"}</span>
          <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: "var(--bg-input)", background: accountColor, border: `1px solid ${accountColor}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{account.isUser ? "사용자" : "시스템"}</span>
          {account.disabled === "예" && <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: "var(--text-dim)", background: "var(--bg-input)", border: "1px solid var(--text-faint)", borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>비활성</span>}
          {account.specialAccount.startsWith("예") && <span title={account.specialAccount} style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>숨김</span>}
        </span>
        <span title={account.rawPath || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: account.path ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" }}>{account.path || "프로필 경로 없음"}</span>
      </span>
      <span title={account.sid} style={{ width: 330, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{account.sid}</span>
      <span style={{ width: 172, flexShrink: 0, textAlign: "right", color: account.created ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{account.created || "생성 시간 없음"}</span>
      <ChevronRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />
    </button>
  );
}

const ACCOUNT_FLAG_DESCRIPTIONS: Record<string, string> = {
  Disabled: "비활성화된 계정입니다.",
  HomeDirRequired: "로그온 시 홈 디렉터리가 필요한 계정입니다.",
  PwNotRequired: "암호가 필수는 아니라는 속성입니다. 현재 암호가 없다는 뜻은 아닙니다.",
  TempDuplicate: "다른 도메인의 기본 계정을 대신하는 로컬 계정입니다.",
  Normal: "일반 사용자 계정 유형입니다. 관리자 권한 여부를 뜻하지 않습니다.",
  MNSLogon: "MNS(Majority Node Set) 로그온 계정 유형입니다.",
  DomainTrust: "다른 도메인과의 신뢰 관계에 사용하는 계정입니다.",
  WorkstationTrust: "도메인에 가입한 워크스테이션 또는 멤버 서버의 컴퓨터 계정입니다.",
  ServerTrust: "도메인 컨트롤러의 컴퓨터 계정입니다.",
  PwNoExpire: "계정 암호가 만료되지 않도록 설정되어 있습니다.",
  AutoLocked: "자동 잠금 상태의 계정입니다.",
};

function AccountFlags({ value }: { value: string }) {
  return <>{value.split(",").map((part, index) => {
    const flag = part.trim();
    return <span key={`${index}:${flag}`}>{index > 0 && ", "}<Tooltip title={ACCOUNT_FLAG_DESCRIPTIONS[flag] ?? "이 속성에 대한 설명이 등록되어 있지 않습니다."} describeChild arrow>
      <span tabIndex={0} style={{ cursor: "help", borderBottom: "1px dotted var(--text-faint)" }}>{flag}</span>
    </Tooltip></span>;
  })}</>;
}

function DetailRow({ label, value, mono, bm, children }: { label: string; value: string; mono?: boolean; bm?: { active: boolean; onToggle: () => void }; children?: React.ReactNode }) {
  return (
    <div className={bm?.active ? "target-info-detail-row dfir-bookmarked-row" : "target-info-detail-row"} style={{ display: "flex", gap: 12, padding: "8px 10px", margin: "0 -10px", borderBottom: "1px solid var(--border-subtle)", borderLeft: "3px solid transparent", background: "transparent", alignItems: "center" }}>
      <span style={{ flex: "0 0 142px", color: "var(--text-dim)", fontSize: 12 }}>{label}</span>
      <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all", fontFamily: mono ? "var(--mono)" : "var(--sans)" }}>
        {children ?? (value || "—")}
      </span>
      {bm && value && (
        <button
          className={bm.active ? "dfir-bookmark-control" : undefined}
          onClick={bm.onToggle}
          title={bm.active ? "이 시각 북마크 해제" : "이 시각 북마크"}
          style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", justifyContent: "center", width: 25, height: 24, padding: 0, borderRadius: "var(--radius)", cursor: "pointer", background: bm.active ? "var(--bookmark-row)" : "transparent", color: bm.active ? "var(--bookmark-control)" : "var(--text-dim)", border: `1px solid ${bm.active ? "var(--bookmark-outline)" : "var(--border)"}` }}
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
  // LogonType is a Windows logon type only in Security auditing events
  // (Shell-Core etc. reuse the name for unrelated flags).
  const logon = row.Provider === "Microsoft-Windows-Security-Auditing" ? val(/logontype/i) : "";
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

function AccountDetailPage({ account, onBack, loadEvents, timeRange, onNavigate, onFetchLinkedRows, isRowBookmarked, onToggleBookmark, accountDirectory }: { account: Account; onBack: () => void; loadEvents?: (query: AccountEventQuery) => Promise<AccountEventPage>; timeRange: TimeRange; onNavigate?: (targetFile: string, targetColumn: string, value: string) => void; onFetchLinkedRows?: FetchLinkedRows; isRowBookmarked?: (row: Row, field?: string) => boolean; onToggleBookmark?: (rowid: number, field: string) => void; accountDirectory?: AccountDirectory }) {
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
  const fieldBookmark = (field: string) =>
    onToggleBookmark
      ? { active: isRowBookmarked?.(account.row, field) ?? false, onToggle: () => onToggleBookmark(account.rowid, field) }
      : undefined;
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
    loadEvents({
      recordId: account.row.record_id || "",
      datasetId: account.row.dataset_id || "",
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
  }, [account.row.record_id, account.row.dataset_id, accountKey, eventSearch, loadEvents, requestedPage, timeRange.end, timeRange.start]);

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
  // Stored result predates account-event storage: re-parse, not "no activity".
  const stale = Boolean(visibleEvents?.stale);
  // The account row came from a result generation that was since replaced.
  const replaced = Boolean(visibleEvents?.replaced);
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
        <button className="nm-btn" onClick={onBack} title="호스트 정보로 돌아가기" aria-label="호스트 정보로 돌아가기" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 31, height: 31, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--accent)", cursor: "pointer", padding: 0, marginRight: 2 }}>
          <ArrowBackOutlinedIcon sx={{ fontSize: 17 }} />
        </button>
        <ManageAccountsOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} aria-hidden="true" />
        <strong style={{ fontSize: 15, color: "var(--text)", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>계정 상세 <span aria-hidden="true" style={{ color: "var(--text-faint)", padding: "0 2px" }}>|</span> {account.username || "(이름 없음)"}</strong>
        <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: "var(--bg-input)", background: account.isUser ? "var(--accent)" : "#d0d0d0", border: `1px solid ${account.isUser ? "var(--accent)" : "#d0d0d0"}`, borderRadius: "var(--radius)", padding: "1px 8px" }}>{account.isUser ? "사용자" : "시스템"}</span>
        {account.disabled === "예" && <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, padding: "1px 8px", border: "1px solid var(--text-faint)", borderRadius: "var(--radius)", color: "var(--text-dim)", background: "var(--bg-input)" }}>비활성</span>}
        {account.fullName && account.fullName !== account.username && <span style={{ color: "var(--text-faint)", fontSize: 12 }}>{account.fullName}</span>}
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6 }}>
          {account.specialAccount.startsWith("예") && <span title={account.specialAccount} style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, padding: "1px 8px", border: "1px solid var(--warning)", borderRadius: "var(--radius)", color: "var(--warning)", whiteSpace: "nowrap" }}>숨김 계정</span>}
        </span>
      </header>
      <div className="target-info-account-detail-scroll" style={{ flex: 1, minHeight: 0, overflowY: "auto", overflowX: "hidden", overscrollBehavior: "contain", padding: "14px 24px 32px" }}>
      {hijack && (
        <div style={{ background: "var(--danger-subtle)", border: "1px solid var(--danger)", borderRadius: "var(--radius)", padding: "10px 14px", marginBottom: 16 }}>
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
            {stateRows.filter(([, value]) => Boolean(value)).map(([label, value]) => <DetailRow key={label} label={label} value={value}>{label === "권한 / 속성" ? <AccountFlags value={value} /> : undefined}</DetailRow>)}
          </DetailGroup>}
          <DetailGroup title="시간 정보">
            {timeRows.map(([label, value, field]) => <DetailRow key={field} label={label} value={value} mono bm={fieldBookmark(field)} />)}
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
            style={{ boxSizing: "border-box", width: "100%", height: 32, marginBottom: 8, padding: "0 10px", background: "var(--bg)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius)", fontFamily: "var(--sans)", fontSize: 12.5, outline: "none" }}
          />}
          {loadEvents && initialLoading && <div style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 48, color: "var(--text-dim)", fontSize: 12.5 }}><CircularProgress size={16} thickness={4} /> 이 계정의 EventLog 활동을 불러오는 중…</div>}
          {loadEvents && refreshing && <div style={{ display: "flex", alignItems: "center", gap: 6, minHeight: 24, marginBottom: 6, color: "var(--text-dim)", fontSize: 11.5 }}><CircularProgress size={14} thickness={4} /> 결과 갱신 중… {showingPriorQuery ? "이전 결과 표시 중" : "현재 결과 확인 중"}</div>}
          {loadEvents && stale && <div style={{ marginBottom: 8, padding: "6px 8px", borderLeft: "2px solid var(--warning)", background: "var(--warning-subtle)", color: "var(--warning)", fontSize: 11.5, lineHeight: 1.35 }}>이전 파싱 결과라 계정 활동이 저장되어 있지 않습니다. 호스트를 다시 파싱하세요.</div>}
          {loadEvents && replaced && <div style={{ marginBottom: 8, padding: "6px 8px", borderLeft: "2px solid var(--warning)", background: "var(--warning-subtle)", color: "var(--warning)", fontSize: 11.5, lineHeight: 1.35 }}>파싱 결과가 교체되었습니다. 호스트 정보를 다시 열어 주세요.</div>}
          {loadEvents && eventsError && <div title={eventsError} style={{ paddingBottom: 8, color: "var(--danger)", fontSize: 12.5 }}>{visibleEvents ? "새 EventLog 결과를 불러오지 못했습니다. 이전 결과 표시 중." : `EventLog 활동을 불러오지 못했습니다: ${eventsError}`}</div>}
          {loadEvents && !initialLoading && visibleEvents && !stale && !replaced && evCount === 0 && <div style={{ fontSize: 12.5, color: "var(--text-faint)" }}>{eventSearch.trim() ? "검색 조건과 기간 필터에 일치하는 EventLog가 없습니다." : "선택한 기간에 이 계정과 관련된 EventLog가 없습니다."}</div>}
          {loadEvents && visibleEvents && evCount > 0 && <div style={{ minWidth: 0, pointerEvents: refreshing ? "none" : "auto", opacity: refreshing ? 0.65 : 1 }}>
          {pagedEvents.map((r, i) => {
            const eid = r.EventID || "";
            const catalogNote = lookupEventCatalog(r.Provider, eid)?.label || (EVENT_LABELS[eid] && EVENT_LABELS[eid] !== `Event ${eid}` ? EVENT_LABELS[eid] : "");
            const summary = eventSummary(r);
            return (
              <button
                type="button"
                key={`${r._record_key || r.EventRecordID || r.timestamp}|${i}`}
                onClick={() => setSelectedEvent(r)}
                onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                style={{ borderRadius: "var(--radius)", display: "flex", alignItems: "center", gap: 10, width: "100%", minHeight: 50, padding: "7px 4px", background: "transparent", border: "none", borderBottom: i < pagedEvents.length - 1 ? "1px solid var(--border-subtle)" : "none", color: "inherit", cursor: "pointer", fontFamily: "inherit", textAlign: "left", transition: "background .15s ease" }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, flexShrink: 0, borderRadius: "var(--radius)", background: "rgba(174, 189, 255, 0.14)" }}>
                  <EventNoteOutlinedIcon sx={{ fontSize: 16, color: "#aebdff" }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                    <span style={{ flexShrink: 0, fontSize: 13, fontWeight: 700, color: "var(--text)" }}>Event {eid || "—"}</span>
                    {catalogNote && <span title={catalogNote} style={{ flexShrink: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#5bc8c0", border: "1px solid #5bc8c0", borderRadius: "var(--radius)", padding: "1px 7px", fontSize: 11, fontWeight: 650 }}>{catalogNote}</span>}
                  </span>
                  <span title={summary || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, color: "var(--text-faint)" }}>{[r.Provider || r._log, summary].filter(Boolean).join(" · ") || "—"}</span>
                </span>
                <span style={{ flexShrink: 0, width: 172, textAlign: "right", fontSize: 12.5, fontWeight: 600, color: r.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{r.timestamp || "시간 정보 없음"}</span>
                <ChevronRightOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0 }} />
              </button>
            );
          })}
          </div>}
          {loadEvents && visibleEvents && evPageCount > 1 && (
            <div style={{ display: "flex", justifyContent: "center", marginTop: 10 }}>
              <PaginationControls ariaLabel="이벤트 페이지" page={renderedSafePage} pageCount={evPageCount} disabled={refreshing} onChange={(next) => { setPageFilterKey(filterKey); setEvPage(next); }} summary={`(${evCount.toLocaleString()}건)`} />
            </div>
          )}
        </DetailSurface>
      </div>
      </div>

      {selectedEvent && (
        <RowDetailPanel
          // Source identity is transport metadata of the account query, not
          // analyst-facing EventLog evidence; keep it out of the full fields.
          row={Object.fromEntries(Object.entries(selectedEvent).filter(([key]) => key !== "_source_full_path" && key !== "_source_table_name" && key !== "__rowid"))}
          columns={Object.keys(selectedEvent).filter((key) => key !== "_source_full_path" && key !== "_source_table_name" && key !== "__rowid")}
          focusedColumn={null}
          fileBaseName="EventLog_Events"
          onClose={() => setSelectedEvent(null)}
          onNavigate={onNavigate ?? (() => {})}
          onFetchLinkedRows={onFetchLinkedRows}
          accountDirectory={accountDirectory}
        />
      )}
    </div>
  );
}

