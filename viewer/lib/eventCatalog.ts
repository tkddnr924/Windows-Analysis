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
  "Microsoft-Windows-Windows Defender|1006": { category: "탐지", label: "악성코드 탐지(검사)" },
  "Microsoft-Windows-Windows Defender|1007": { category: "탐지", label: "악성코드 조치 수행" },
  "Microsoft-Windows-Windows Defender|1008": { category: "탐지", label: "악성코드 조치 실패" },
  "Microsoft-Windows-Windows Defender|1009": { category: "탐지", label: "격리 항목 복원" },
  "Microsoft-Windows-Windows Defender|1015": { category: "탐지", label: "의심 동작 탐지" },
  "Microsoft-Windows-Windows Defender|5007": { category: "탐지", label: "Defender 설정 변경" },
  "Microsoft-Windows-Windows Defender|5010": { category: "탐지", label: "바이러스 검사 사용 안 함" },
  "Microsoft-Windows-Windows Defender|5012": { category: "탐지", label: "바이러스 검사(파일) 사용 안 함" },

  // --- 부팅 / 종료 / 전원 (세션 타임라인의 기준점) ---
  "EventLog|6005": { category: "시스템", label: "이벤트 로그 서비스 시작(부팅 시점)" },
  "EventLog|6006": { category: "시스템", label: "이벤트 로그 서비스 정상 종료" },
  "EventLog|6008": { category: "시스템", label: "비정상 종료(예기치 않은 종료)" },
  "EventLog|6013": { category: "시스템", label: "시스템 가동 시간" },
  "EventLog|1100": { category: "시스템", label: "이벤트 로그 서비스 종료" },
  "USER32|1074": { category: "시스템", label: "시스템 종료/재시작 요청(사용자/프로세스)" },
  "User32|1074": { category: "시스템", label: "시스템 종료/재시작 요청(사용자/프로세스)" },
  "Microsoft-Windows-Kernel-General|12": { category: "시스템", label: "운영체제 시작" },
  "Microsoft-Windows-Kernel-General|13": { category: "시스템", label: "운영체제 종료" },
  "Microsoft-Windows-Kernel-Power|41": { category: "시스템", label: "비정상 재부팅(전원 손실 등)" },
  "Microsoft-Windows-Kernel-Power|42": { category: "시스템", label: "절전 모드 진입" },
  "Microsoft-Windows-Power-Troubleshooter|1": { category: "시스템", label: "절전 해제(기상)" },
  "Microsoft-Windows-Winlogon|7001": { category: "로그온", label: "대화형 로그온" },
  "Microsoft-Windows-Winlogon|7002": { category: "로그온", label: "대화형 로그오프" },
  "Microsoft-Windows-User Profiles Service|1": { category: "로그온", label: "사용자 프로필 로드 시작" },
  "Microsoft-Windows-User Profiles Service|2": { category: "로그온", label: "사용자 프로필 로드 완료" },

  // --- 서비스 (영속성 / 측면 이동) ---
  "Service Control Manager|7000": { category: "서비스", label: "서비스 시작 실패" },
  "Service Control Manager|7009": { category: "서비스", label: "서비스 시작 시간 초과" },
  "Service Control Manager|7034": { category: "서비스", label: "서비스 비정상 종료" },
  "Service Control Manager|7035": { category: "서비스", label: "서비스 제어 신호(시작/정지)" },
  "Service Control Manager|7036": { category: "서비스", label: "서비스 상태 변경(시작됨/중지됨)" },
  "Service Control Manager|7040": { category: "서비스", label: "서비스 시작 유형 변경" },

  // --- 보안 감사 (프로세스/권한/영속성/계정) ---
  "Microsoft-Windows-Security-Auditing|4688": { category: "실행", label: "새 프로세스 생성" },
  "Microsoft-Windows-Security-Auditing|4689": { category: "실행", label: "프로세스 종료" },
  "Microsoft-Windows-Security-Auditing|4657": { category: "레지스트리", label: "레지스트리 값 수정" },
  "Microsoft-Windows-Security-Auditing|4663": { category: "객체 접근", label: "객체 접근 시도" },
  "Microsoft-Windows-Security-Auditing|4670": { category: "권한", label: "객체 권한 변경" },
  "Microsoft-Windows-Security-Auditing|4673": { category: "권한", label: "특권 서비스 호출" },
  "Microsoft-Windows-Security-Auditing|4719": { category: "안티포렌식", label: "감사 정책 변경" },
  "Microsoft-Windows-Security-Auditing|4738": { category: "계정", label: "사용자 계정 변경" },
  "Microsoft-Windows-Security-Auditing|4767": { category: "계정", label: "계정 잠금 해제" },
  "Microsoft-Windows-Security-Auditing|4700": { category: "영속성", label: "예약 작업 사용" },
  "Microsoft-Windows-Security-Auditing|4701": { category: "영속성", label: "예약 작업 사용 안 함" },
  "Microsoft-Windows-Security-Auditing|4702": { category: "영속성", label: "예약 작업 업데이트" },
  "Microsoft-Windows-Security-Auditing|4778": { category: "RDP", label: "세션 재연결" },
  "Microsoft-Windows-Security-Auditing|4779": { category: "RDP", label: "세션 연결 끊김" },
  "Microsoft-Windows-Security-Auditing|4798": { category: "계정", label: "사용자 로컬 그룹 멤버 열거" },
  "Microsoft-Windows-Security-Auditing|4799": { category: "그룹", label: "보안 그룹 멤버 열거" },
  "Microsoft-Windows-Security-Auditing|4964": { category: "로그온", label: "특수 그룹 로그온" },
  "Microsoft-Windows-Security-Auditing|5379": { category: "자격증명", label: "자격 증명 관리자 읽기" },

  // --- 예약 작업 (영속성 / 실행) ---
  "Microsoft-Windows-TaskScheduler|140": { category: "영속성", label: "예약 작업 등록됨" },
  "Microsoft-Windows-TaskScheduler|141": { category: "영속성", label: "예약 작업 삭제됨" },
  "Microsoft-Windows-TaskScheduler|129": { category: "실행", label: "예약 작업 프로세스 생성" },
  "Microsoft-Windows-TaskScheduler|201": { category: "실행", label: "예약 작업 동작 완료" },

  // --- PowerShell / 원격 실행 ---
  "Microsoft-Windows-PowerShell|4103": { category: "PowerShell", label: "모듈/파이프라인 실행 기록" },
  "Microsoft-Windows-PowerShell|4100": { category: "PowerShell", label: "실행 오류" },
  "PowerShell|400": { category: "PowerShell", label: "엔진 시작" },
  "PowerShell|600": { category: "PowerShell", label: "공급자 시작" },
  "Microsoft-Windows-WinRM|91": { category: "원격", label: "WinRM 세션 생성" },
  "Microsoft-Windows-WinRM|168": { category: "원격", label: "WinRM 인증" },

  // --- BITS (공격자 다운로드 수단으로 악용) ---
  "Microsoft-Windows-Bits-Client|3": { category: "다운로드", label: "BITS 전송 작업 생성" },
  "Microsoft-Windows-Bits-Client|59": { category: "다운로드", label: "BITS 전송 시작" },
  "Microsoft-Windows-Bits-Client|60": { category: "다운로드", label: "BITS 전송 완료" },

  // --- RDP 세부 ---
  "Microsoft-Windows-TerminalServices-LocalSessionManager|23": { category: "RDP", label: "RDP 세션 로그오프" },
  "Microsoft-Windows-TerminalServices-LocalSessionManager|39": { category: "RDP", label: "RDP 세션 연결 끊김(다른 세션에 의해)" },
  "Microsoft-Windows-TerminalServices-LocalSessionManager|40": { category: "RDP", label: "RDP 세션 연결 끊김(사유 코드)" },
  "Microsoft-Windows-TerminalServices-RemoteConnectionManager|1158": { category: "RDP", label: "원격 연결 수락" },

  // --- 응용 프로그램 오류 (크래시/익스플로잇 정황) ---
  "Application Error|1000": { category: "오류", label: "응용 프로그램 크래시" },
  "Application Hang|1002": { category: "오류", label: "응용 프로그램 응답 없음" },
  "Windows Error Reporting|1001": { category: "오류", label: "오류 보고(WER)" },
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

  if (eventId === "1102")
    tags.push({ label: "감사 로그 삭제(안티포렌식 의심)", severity: "danger", description: "보안 감사 로그가 지워졌습니다. 공격자가 침입 흔적을 없애려는 안티포렌식 행위의 대표 신호입니다." });
  if (eventId === "4625")
    tags.push({ label: "로그온 실패", severity: "warning", description: "로그온 시도가 실패했습니다. 단발성은 흔하지만, 짧은 시간에 반복되면 무차별 대입(브루트포스)·패스워드 스프레이 정황일 수 있습니다." });
  if (eventId === "4648")
    tags.push({ label: "명시적 자격 증명 로그온(계정 전환/측면 이동 의심)", severity: "warning", description: "현재 세션과 다른 계정의 자격 증명을 명시적으로 사용해 로그온했습니다. 계정 전환이나 내부 측면 이동(lateral movement)에서 자주 관찰됩니다." });

  if (eventId === "4624" && data?.LogonType != null) {
    const logonType = String(data.LogonType);
    if (logonType === "10")
      tags.push({ label: "원격 데스크톱(RDP) 로그온", severity: "warning", description: "LogonType 10 — RDP 등 원격 대화형 로그온입니다. 원격 접속 자체가 침해 시 공격자의 주요 이동 경로라 확인 대상입니다." });
    if (logonType === "3")
      tags.push({ label: "네트워크 로그온(SMB 등)", severity: "warning", description: "LogonType 3 — 파일 공유(SMB) 등 네트워크 로그온입니다. 내부 자원 접근·측면 이동 추적의 단서가 됩니다." });
  }

  if (["4728", "4732", "4756"].includes(eventId)) {
    const group = String(data?.TargetUserName ?? "");
    const isAdminGroup = /admin|관리자/i.test(group);
    tags.push({
      label: `그룹 멤버 추가${isAdminGroup ? " (관리자 그룹)" : ""}`,
      severity: isAdminGroup ? "danger" : "warning",
      description: isAdminGroup
        ? "관리자 그룹에 계정이 추가되었습니다. 권한 상승(privilege escalation)의 직접적 흔적으로, 승인된 변경인지 반드시 확인해야 합니다."
        : "보안 그룹에 계정이 추가되었습니다. 권한 변경 흔적이니 정상적인 관리 작업인지 확인이 필요합니다.",
    });
  }

  if (eventId === "7045" || (provider === "Microsoft-Windows-Security-Auditing" && eventId === "4697")) {
    tags.push({ label: "새 서비스 설치(영속성 기법 가능)", severity: "warning", description: "새 Windows 서비스가 설치되었습니다. 재부팅에도 살아남는 실행 수단이라, 공격자가 지속성(persistence) 확보에 흔히 악용합니다." });
  }
  if (eventId === "4698" || (provider === "Microsoft-Windows-TaskScheduler" && eventId === "106")) {
    tags.push({ label: "예약 작업 생성(영속성 기법 가능)", severity: "warning", description: "예약 작업이 생성되었습니다. 특정 시각·이벤트에 자동 실행되므로 지속성·정기 실행 확보 수단으로 자주 쓰입니다." });
  }
  if (["5140", "5145"].includes(eventId)) {
    tags.push({ label: "네트워크 공유(SMB) 접근", severity: "warning", description: "네트워크 공유에 접근했습니다. 내부 파일 서버·관리 공유(ADMIN$, C$) 접근은 측면 이동·데이터 수집 정황일 수 있습니다." });
  }
  if (eventId === "5156") tags.push({ label: "외부/네트워크 연결 허용", severity: "warning", description: "방화벽이 연결을 허용했습니다. 외부와의 통신 흔적으로, C2 통신·데이터 유출 추적의 단서가 됩니다." });
  if (eventId === "1149") tags.push({ label: "RDP 원격 접속 성공", severity: "warning", description: "RDP 클라이언트 인증이 성공했습니다(원격 접속 성립). 원격 접속 경로 확인 대상입니다." });
  if (eventId === "5861") tags.push({ label: "WMI 영구 이벤트 구독(영속성 기법 가능)", severity: "danger", description: "WMI 영구 이벤트 구독이 등록되었습니다. 디스크에 파일을 거의 남기지 않는 은밀한 지속성 기법으로, 정상 환경에서는 드뭅니다." });
  if (eventId === "1116") tags.push({ label: "백신 악성코드 탐지", severity: "danger", description: "Windows Defender가 악성코드를 탐지했습니다. 실제 위협이 이 시스템에 존재했다는 직접 증거입니다." });
  if (eventId === "5001") tags.push({ label: "실시간 보호 비활성화", severity: "danger", description: "Defender 실시간 보호가 꺼졌습니다. 공격자가 탐지를 회피하려고 백신을 무력화하는 전형적 행위입니다." });
  if (eventId === "4720") tags.push({ label: "계정 생성", severity: "warning", description: "새 사용자 계정이 생성되었습니다. 공격자가 지속적 접근용 백도어 계정을 만드는 경우가 있어 확인 대상입니다." });

  if (eventId === "4104" && typeof data?.ScriptBlockText === "string" && SUSPICIOUS_POWERSHELL_PATTERN.test(data.ScriptBlockText)) {
    tags.push({ label: "의심스러운 PowerShell 실행(인코딩/다운로드/난독화 패턴)", severity: "danger", description: "PowerShell 스크립트에서 인코딩(-enc)·다운로드 크래들(DownloadString 등)·숨김 창·실행정책 우회 같은 공격성 패턴이 감지됐습니다. 전체 스크립트 내용을 직접 확인하세요." });
  }

  if (eventId === "4719")
    tags.push({ label: "감사 정책 변경(안티포렌식 의심)", severity: "danger", description: "보안 감사 정책이 변경되었습니다. 공격자가 특정 행위가 로그에 남지 않도록 감사를 꺼두는 방어 회피/안티포렌식 수법일 수 있습니다." });

  if (provider === "Microsoft-Windows-Windows Defender" && ["5010", "5012"].includes(eventId))
    tags.push({ label: "백신 검사 비활성화", severity: "danger", description: "Windows Defender 검사가 비활성화되었습니다. 탐지를 피하려고 백신을 무력화하는 전형적 방어 회피 행위입니다." });

  if (provider === "Microsoft-Windows-Windows Defender" && ["1006", "1015"].includes(eventId))
    tags.push({ label: "백신 위협 탐지", severity: "danger", description: "Windows Defender가 악성코드 또는 의심 동작을 탐지했습니다. 실제 위협이 이 시스템에 존재했다는 직접 증거입니다." });

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
