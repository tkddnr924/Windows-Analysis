// Windows privilege (Se*Privilege) reference — turns a bare privilege name
// list (as in Security event 4672/4673) into readable text. Descriptions are
// plain "what this privilege is" statements, no risk judgment: these
// privileges appearing on an admin/service logon is normal, so flagging them
// as dangerous would mislead.

export const PRIVILEGE_INFO: Record<string, string> = {
  SeTcbPrivilege: "운영체제의 일부로 동작",
  SeCreateTokenPrivilege: "액세스 토큰 생성",
  SeDebugPrivilege: "프로그램 디버그",
  SeBackupPrivilege: "파일 및 디렉터리 백업",
  SeRestorePrivilege: "파일 및 디렉터리 복원",
  SeLoadDriverPrivilege: "장치 드라이버 로드 및 언로드",
  SeTakeOwnershipPrivilege: "파일/개체의 소유권 획득",
  SeImpersonatePrivilege: "인증 후 클라이언트 가장(impersonate)",
  SeAssignPrimaryTokenPrivilege: "프로세스에 기본 토큰 할당",
  SeSecurityPrivilege: "보안 로그 관리 및 감사",
  SeSystemtimePrivilege: "시스템 시간 변경",
  SeAuditPrivilege: "보안 감사 로그 생성",
  SeEnableDelegationPrivilege: "계정의 위임 신뢰 설정",
  SeTrustedCredManAccessPrivilege: "자격 증명 관리자에 신뢰된 호출자로 접근",
  SeRelabelPrivilege: "개체의 무결성 레이블 수정",
  SeSystemEnvironmentPrivilege: "펌웨어 환경 값(UEFI/NVRAM) 수정",
  SeDelegateSessionUserImpersonatePrivilege: "다른 세션 사용자 가장",
  SeChangeNotifyPrivilege: "폴더 통과 확인 우회(대부분 계정 기본 보유)",
  SeShutdownPrivilege: "시스템 종료",
  SeRemoteShutdownPrivilege: "원격에서 시스템 종료",
  SeSystemProfilePrivilege: "시스템 성능 프로파일링",
  SeProfileSingleProcessPrivilege: "단일 프로세스 프로파일링",
  SeIncreaseBasePriorityPrivilege: "스케줄링 우선순위 조정",
  SeCreatePagefilePrivilege: "페이지 파일 생성",
  SeCreatePermanentPrivilege: "영구 공유 개체 생성",
  SeIncreaseQuotaPrivilege: "프로세스 메모리 할당량 조정",
  SeIncreaseWorkingSetPrivilege: "프로세스 작업 집합 크기 증가",
  SeManageVolumePrivilege: "볼륨 유지 관리 작업 수행",
  SeCreateGlobalPrivilege: "전역 네임스페이스 개체 생성",
  SeCreateSymbolicLinkPrivilege: "심볼릭 링크 생성",
  SeTimeZonePrivilege: "표준 시간대 변경",
  SeUndockPrivilege: "도킹 스테이션에서 분리",
  SeMachineAccountPrivilege: "도메인에 워크스테이션 추가",
  SeLockMemoryPrivilege: "물리 메모리에 페이지 고정",
};

// Splits a raw PrivilegeList blob (whitespace/newline/comma separated) into
// individual privilege tokens, ignoring wrapping/stray fragments.
export function parsePrivileges(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => /^Se[A-Za-z]+Privilege$/.test(s));
}

export function lookupPrivilege(name: string): string | null {
  return PRIVILEGE_INFO[name] ?? null;
}
