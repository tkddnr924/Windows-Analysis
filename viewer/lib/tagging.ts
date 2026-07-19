export type TagSeverity = "warning" | "danger";

export interface Tag {
  label: string;
  severity: TagSeverity;
  /** Why this is a triage signal — shown on hover. */
  description?: string;
}

interface PathRule {
  pattern: RegExp;
  label: string;
  severity: TagSeverity;
  description: string;
}

// Weak-but-useful signals for triage — a hit here means "worth a closer
// look", not "confirmed malicious". Applied to any field that holds a
// filesystem path (execution path, target path, download path, ...).
const SUSPICIOUS_PATH_RULES: PathRule[] = [
  {
    pattern: /\\(?:appdata\\local\\)?temp\\/i,
    label: "임시 폴더 실행",
    severity: "warning",
    description: "임시(Temp) 폴더는 정상 프로그램이 상주하는 곳이 아닙니다. 악성코드가 실행 파일을 잠깐 풀어 실행하는 대표적 위치라, 여기서 실행된 흔적은 확인이 필요합니다.",
  },
  {
    pattern: /\\downloads\\/i,
    label: "다운로드 폴더 실행",
    severity: "warning",
    description: "다운로드 폴더에서 바로 실행된 파일입니다. 사용자가 받은 파일이 그대로 실행된 흔적으로, 피싱 첨부·드라이브바이 등 초기 침투 경로일 수 있습니다.",
  },
  {
    pattern: /\\users\\public\\/i,
    label: "Public 폴더 실행",
    severity: "warning",
    description: "Public 폴더는 모든 사용자가 쓰기 가능해 권한이 낮아도 파일을 놓기 쉽습니다. 공격자가 도구·페이로드를 임시로 두는 위치로 자주 악용됩니다.",
  },
  {
    pattern: /\\programdata\\(?!microsoft\\)/i,
    label: "ProgramData 실행",
    severity: "warning",
    description: "ProgramData는 쓰기가 비교적 자유롭고 사용자 눈에 잘 띄지 않아, 악성코드가 지속성 확보용 파일을 숨겨두는 위치로 악용됩니다.",
  },
  {
    pattern: /\\(powershell|wscript|cscript|mshta|regsvr32|rundll32|certutil)\.exe/i,
    label: "LOLBin 실행",
    severity: "danger",
    description: "LOLBin(Living-off-the-Land Binary): powershell·rundll32·regsvr32·mshta·certutil 같은 Windows 정품 도구를 공격자가 악성코드 다운로드·실행에 악용하는 기법입니다. 파일 자체는 정상 서명이라 백신 탐지를 우회하기 쉬워 위험 신호로 봅니다.",
  },
];

export function tagsForPath(path: string | undefined | null): Tag[] {
  if (!path) return [];
  const tags: Tag[] = [];
  for (const rule of SUSPICIOUS_PATH_RULES) {
    if (rule.pattern.test(path)) tags.push({ label: rule.label, severity: rule.severity, description: rule.description });
  }
  return tags;
}

export function tagsForEventLevel(level: string | undefined | null): Tag[] {
  if (level === "Critical")
    return [{ label: "치명적 이벤트", severity: "danger", description: "Windows가 Critical(치명적)로 기록한 이벤트입니다. 시스템 충돌·비정상 종료 등 심각한 상태를 뜻합니다." }];
  if (level === "Error")
    return [{ label: "오류 이벤트", severity: "danger", description: "Windows가 Error(오류)로 기록한 이벤트입니다. 구성요소 실패나 비정상 동작의 흔적일 수 있습니다." }];
  return [];
}

export function tagsForBoolean(value: string | undefined | null, whenTrue: Tag): Tag[] {
  return value === "True" || value === "true" || value === "1" ? [whenTrue] : [];
}

// Classic masquerading check: malware often keeps a legitimate-looking
// filename on disk while its PE metadata (OriginalFileName) still names
// the real payload — or copies a real system binary's name over a
// different original identity. A mismatch doesn't confirm malice (some
// legit installers rename freely) but it's exactly the kind of thing an
// analyst wants surfaced, not buried in a raw field dump.
export function tagsForNameMismatch(actualName: string | undefined | null, originalFileName: string | undefined | null): Tag[] {
  if (!actualName || !originalFileName) return [];
  const a = actualName.trim().toLowerCase();
  const o = originalFileName.trim().toLowerCase();
  if (a === o) return [];
  // ignore trivial extension-only differences (e.g. name without .exe)
  const stripExt = (s: string) => s.replace(/\.[a-z0-9]+$/i, "");
  if (stripExt(a) === stripExt(o)) return [];
  return [
    {
      label: `파일명 불일치 (내부명: ${originalFileName})`,
      severity: "danger",
      description: "디스크상의 파일명과 PE 내부 원본 파일명(OriginalFileName)이 다릅니다. 정상 파일로 위장(마스커레이딩)하는 전형적 수법으로, 악성코드가 신뢰받는 이름을 흉내 낼 때 자주 나타납니다.",
    },
  ];
}

// Chromium's DownloadDangerType — the browser's own verdict on a
// download, straight from Safe Browsing. 0 is "not dangerous"; several
// other values ARE the browser telling you it thought this was malware.
const DANGEROUS_DOWNLOAD_TYPES: Record<string, string> = {
  "1": "위험 파일로 판정",
  "2": "위험 URL로 판정",
  "3": "위험 콘텐츠로 판정",
  "4": "위험 의심 콘텐츠",
  "7": "위험 호스트로 판정",
  "8": "잠재적 유해 프로그램(PUP)",
};

export function tagsForDangerType(dangerType: string | undefined | null): Tag[] {
  if (!dangerType) return [];
  const label = DANGEROUS_DOWNLOAD_TYPES[dangerType];
  return label
    ? [
        {
          label: `브라우저 자체 위험 판정: ${label}`,
          severity: "danger",
          description: "브라우저의 Safe Browsing이 다운로드 시점에 스스로 위험하다고 판정한 파일입니다. 휴리스틱이 아니라 브라우저가 직접 남긴 판정값이라 신뢰도가 높습니다.",
        },
      ]
    : [];
}
