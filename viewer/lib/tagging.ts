export type TagSeverity = "warning" | "danger";

export interface Tag {
  label: string;
  severity: TagSeverity;
}

interface PathRule {
  pattern: RegExp;
  label: string;
  severity: TagSeverity;
}

// Weak-but-useful signals for triage — a hit here means "worth a closer
// look", not "confirmed malicious". Applied to any field that holds a
// filesystem path (execution path, target path, download path, ...).
const SUSPICIOUS_PATH_RULES: PathRule[] = [
  { pattern: /\\(?:appdata\\local\\)?temp\\/i, label: "임시 폴더 실행", severity: "warning" },
  { pattern: /\\downloads\\/i, label: "다운로드 폴더 실행", severity: "warning" },
  { pattern: /\\users\\public\\/i, label: "Public 폴더 실행", severity: "warning" },
  { pattern: /\\programdata\\(?!microsoft\\)/i, label: "ProgramData 실행", severity: "warning" },
  { pattern: /\\(powershell|wscript|cscript|mshta|regsvr32|rundll32|certutil)\.exe/i, label: "LOLBin 실행", severity: "danger" },
];

export function tagsForPath(path: string | undefined | null): Tag[] {
  if (!path) return [];
  const tags: Tag[] = [];
  for (const rule of SUSPICIOUS_PATH_RULES) {
    if (rule.pattern.test(path)) tags.push({ label: rule.label, severity: rule.severity });
  }
  return tags;
}

export function tagsForEventLevel(level: string | undefined | null): Tag[] {
  if (level === "Critical") return [{ label: "치명적 이벤트", severity: "danger" }];
  if (level === "Error") return [{ label: "오류 이벤트", severity: "danger" }];
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
  return [{ label: `파일명 불일치 (내부명: ${originalFileName})`, severity: "danger" }];
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
  return label ? [{ label: `브라우저 자체 위험 판정: ${label}`, severity: "danger" }] : [];
}
