import type { Tag } from "./tagging";

// EventID meaning is ambiguous on its own — the same number means different
// things under different providers (e.g. "21" is an RDP session logon under
// TerminalServices-LocalSessionManager but a Task Scheduler event under a
// different provider). Always key lookups by Provider+EventID together.
export function parseEventData(raw: string | undefined | null): Record<string, unknown> | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw);
    return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// Security-Auditing's LogonType field on 4624/4625/4648 — the single most
// IR-relevant fact about a logon event: type 10 is RDP, type 3 is the
// network logon behind SMB/share access, type 2 is a local console logon.
export const LOGON_TYPE_LABELS: Record<string, string> = {
  "2": "대화형(콘솔)",
  "3": "네트워크(SMB 등)",
  "4": "배치",
  "5": "서비스",
  "7": "잠금 해제",
  "8": "네트워크(평문 암호)",
  "9": "새 자격 증명(RunAs)",
  "10": "원격 데스크톱(RDP)",
  "11": "캐시된 자격 증명",
};

interface EventCatalogEntry {
  category: string;
  label: string;
}

// A curated set of Provider+EventID combinations that matter for incident
// response — remote logon (RDP and network logon types), outbound/inbound
// network connections, SMB share access, persistence (services, scheduled
// tasks, WMI subscriptions), account/group changes, and anti-forensics
// (audit log clearing). Not exhaustive — extend as new providers show up.
const EVENT_CATALOG: Record<string, EventCatalogEntry> = {
  "Microsoft-Windows-Security-Auditing|4624": { category: "로그온", label: "로그온 성공" },
  "Microsoft-Windows-Security-Auditing|4625": { category: "로그온", label: "로그온 실패" },
  "Microsoft-Windows-Security-Auditing|4634": { category: "로그온", label: "로그오프" },
  "Microsoft-Windows-Security-Auditing|4647": { category: "로그온", label: "사용자 로그오프 요청" },
  "Microsoft-Windows-Security-Auditing|4648": { category: "로그온", label: "명시적 자격 증명으로 로그온" },
  "Microsoft-Windows-Security-Auditing|4672": { category: "권한", label: "관리자 권한으로 로그온" },
  "Microsoft-Windows-Security-Auditing|4720": { category: "계정", label: "계정 생성" },
  "Microsoft-Windows-Security-Auditing|4722": { category: "계정", label: "계정 활성화" },
  "Microsoft-Windows-Security-Auditing|4724": { category: "계정", label: "암호 재설정 시도" },
  "Microsoft-Windows-Security-Auditing|4726": { category: "계정", label: "계정 삭제" },
  "Microsoft-Windows-Security-Auditing|4740": { category: "계정", label: "계정 잠김" },
  "Microsoft-Windows-Security-Auditing|4728": { category: "그룹", label: "전역 그룹에 멤버 추가" },
  "Microsoft-Windows-Security-Auditing|4732": { category: "그룹", label: "지역 그룹에 멤버 추가" },
  "Microsoft-Windows-Security-Auditing|4756": { category: "그룹", label: "유니버설 그룹에 멤버 추가" },
  "Microsoft-Windows-Security-Auditing|4698": { category: "영속성", label: "예약 작업 생성" },
  "Microsoft-Windows-Security-Auditing|4697": { category: "영속성", label: "서비스 설치(보안 로그)" },
  "Microsoft-Windows-Security-Auditing|1102": { category: "안티포렌식", label: "감사 로그 삭제" },
  "Microsoft-Windows-Security-Auditing|5140": { category: "SMB", label: "네트워크 공유 접근" },
  "Microsoft-Windows-Security-Auditing|5145": { category: "SMB", label: "공유 파일 상세 접근 검사" },
  "Microsoft-Windows-Security-Auditing|5156": { category: "네트워크", label: "연결 허용(방화벽)" },
  "Microsoft-Windows-Security-Auditing|5157": { category: "네트워크", label: "연결 차단(방화벽)" },
  "Microsoft-Windows-Security-Auditing|4768": { category: "Kerberos", label: "Kerberos TGT 발급 요청" },
  "Microsoft-Windows-Security-Auditing|4769": { category: "Kerberos", label: "Kerberos 서비스 티켓 요청" },
  "Microsoft-Windows-Security-Auditing|4771": { category: "Kerberos", label: "Kerberos 사전 인증 실패" },
  "Microsoft-Windows-Security-Auditing|4776": { category: "인증", label: "NTLM 자격 증명 확인" },
  "Service Control Manager|7045": { category: "영속성", label: "새 서비스 설치" },
  "Microsoft-Windows-TerminalServices-RemoteConnectionManager|1149": { category: "RDP", label: "RDP 클라이언트 인증 성공(원격 접속)" },
  "Microsoft-Windows-TerminalServices-LocalSessionManager|21": { category: "RDP", label: "RDP 세션 로그온" },
  "Microsoft-Windows-TerminalServices-LocalSessionManager|24": { category: "RDP", label: "RDP 세션 연결 끊김" },
  "Microsoft-Windows-TerminalServices-LocalSessionManager|25": { category: "RDP", label: "RDP 세션 재연결" },
  "Microsoft-Windows-PowerShell|4104": { category: "PowerShell", label: "스크립트 블록 실행 기록" },
  "Microsoft-Windows-TaskScheduler|106": { category: "영속성", label: "예약 작업 등록" },
  "Microsoft-Windows-TaskScheduler|200": { category: "실행", label: "예약 작업 실행됨" },
  "Microsoft-Windows-WMI-Activity|5861": { category: "영속성", label: "WMI 영구 이벤트 구독 등록" },
  "Microsoft-Windows-Windows Defender|1116": { category: "탐지", label: "악성코드 탐지" },
  "Microsoft-Windows-Windows Defender|1117": { category: "탐지", label: "악성코드 조치 완료" },
  "Microsoft-Windows-Windows Defender|5001": { category: "탐지", label: "실시간 보호 사용 안 함" },
};

export function lookupEventCatalog(provider: string | undefined, eventId: string | undefined): EventCatalogEntry | null {
  if (!provider || !eventId) return null;
  return EVENT_CATALOG[`${provider}|${eventId}`] ?? null;
}

// Rough signal for obfuscated/download-cradle PowerShell — a real analyst
// still reads the full ScriptBlockText, this just flags candidates.
const SUSPICIOUS_POWERSHELL_PATTERN = /-enc\b|-e\s+[A-Za-z0-9+/=]{20}|invoke-expression|iex[\s(]|downloadstring|downloadfile|frombase64string|-w(indowstyle)?\s+hidden|-nop\b|bypass/i;

export function tagsForSecurityEvent(
  provider: string | undefined,
  eventId: string | undefined,
  eventDataRaw: string | undefined
): Tag[] {
  if (!eventId) return [];
  const data = parseEventData(eventDataRaw);
  const tags: Tag[] = [];

  if (eventId === "1102") tags.push({ label: "감사 로그 삭제(안티포렌식 의심)", severity: "danger" });
  if (eventId === "4625") tags.push({ label: "로그온 실패", severity: "warning" });
  if (eventId === "4648") tags.push({ label: "명시적 자격 증명 로그온(계정 전환/측면 이동 의심)", severity: "warning" });

  if (eventId === "4624" && data?.LogonType != null) {
    const logonType = String(data.LogonType);
    if (logonType === "10") tags.push({ label: "원격 데스크톱(RDP) 로그온", severity: "warning" });
    if (logonType === "3") tags.push({ label: "네트워크 로그온(SMB 등)", severity: "warning" });
  }

  if (["4728", "4732", "4756"].includes(eventId)) {
    const group = String(data?.TargetUserName ?? "");
    const isAdminGroup = /admin|관리자/i.test(group);
    tags.push({ label: `그룹 멤버 추가${isAdminGroup ? " (관리자 그룹)" : ""}`, severity: isAdminGroup ? "danger" : "warning" });
  }

  if (eventId === "7045" || (provider === "Microsoft-Windows-Security-Auditing" && eventId === "4697")) {
    tags.push({ label: "새 서비스 설치(영속성 기법 가능)", severity: "warning" });
  }
  if (eventId === "4698" || (provider === "Microsoft-Windows-TaskScheduler" && eventId === "106")) {
    tags.push({ label: "예약 작업 생성(영속성 기법 가능)", severity: "warning" });
  }
  if (["5140", "5145"].includes(eventId)) {
    tags.push({ label: "네트워크 공유(SMB) 접근", severity: "warning" });
  }
  if (eventId === "5156") tags.push({ label: "외부/네트워크 연결 허용", severity: "warning" });
  if (eventId === "1149") tags.push({ label: "RDP 원격 접속 성공", severity: "warning" });
  if (eventId === "5861") tags.push({ label: "WMI 영구 이벤트 구독(영속성 기법 가능)", severity: "danger" });
  if (eventId === "1116") tags.push({ label: "백신 악성코드 탐지", severity: "danger" });
  if (eventId === "5001") tags.push({ label: "실시간 보호 비활성화", severity: "danger" });
  if (eventId === "4720") tags.push({ label: "계정 생성", severity: "warning" });

  if (eventId === "4104" && typeof data?.ScriptBlockText === "string" && SUSPICIOUS_POWERSHELL_PATTERN.test(data.ScriptBlockText)) {
    tags.push({ label: "의심스러운 PowerShell 실행(인코딩/다운로드/난독화 패턴)", severity: "danger" });
  }

  return tags;
}

// A single squashed "summary" string can't be sorted or filtered per field —
// pull the handful of fields that matter across most security events out as
// their OWN columns, so the table itself (not just the detail panel) shows
// logon type, target account, remote IP, share name, etc. side by side for
// every row at once, each independently sortable/filterable.
export interface EventQuickField {
  jsonKey: string;
  label: string;
  valueLabels?: Record<string, string>;
}

export const EVENT_QUICK_FIELDS: EventQuickField[] = [
  { jsonKey: "LogonType", label: "로그온 유형", valueLabels: LOGON_TYPE_LABELS },
  { jsonKey: "TargetUserName", label: "대상 계정" },
  { jsonKey: "TargetDomainName", label: "대상 도메인" },
  { jsonKey: "IpAddress", label: "원격 IP" },
  { jsonKey: "WorkstationName", label: "워크스테이션" },
  { jsonKey: "ShareName", label: "공유 이름(SMB)" },
  { jsonKey: "ServiceName", label: "서비스 이름" },
  { jsonKey: "TaskName", label: "예약 작업 이름" },
];

export function extractEventField(row: Record<string, string>, jsonKey: string): string {
  const data = parseEventData(row.EventData);
  const value = data?.[jsonKey];
  return value === undefined || value === null || value === "" ? "" : String(value);
}
