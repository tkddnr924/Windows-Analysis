// UserAssist 등에서 경로 앞에 붙는 KNOWNFOLDERID GUID를 실제 폴더 경로로
// 변환한다. Windows 표준 기본 위치 기준이며, 사용자 폴더는 계정마다 다르므로
// <계정> 자리로 표기한다. 매핑에 없는 GUID는 변환하지 않는다(null).
const KNOWN_FOLDER_PATHS: Record<string, string> = {
  // 시작 메뉴/프로그램
  "0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs",
  "A4115719-D62E-491D-AA7C-E74B8BE3B067": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu",
  "A77F5D77-2E2B-44C3-A6A2-ABA601054A51": "C:\\Users\\<계정>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
  "625B53C3-AB48-4EC1-BA1F-A1EF4146FC19": "C:\\Users\\<계정>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu",
  "B97D20BB-F46A-4C97-BA10-5E3608430854": "C:\\Users\\<계정>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
  "82A5EA35-D9CD-47C5-9629-E15D2F714E6E": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
  "9E3995AB-1F9C-4F13-B827-48B24B6C7174": "C:\\Users\\<계정>\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
  // 프로그램/시스템
  "905E63B6-C1BF-494E-B29C-65B732D3D21A": "C:\\Program Files",
  "6D809377-6AF0-444B-8957-A3773F02200E": "C:\\Program Files",
  "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": "C:\\Program Files (x86)",
  "F38BF404-1D43-42F2-9305-67DE0B28FC23": "C:\\Windows",
  "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": "C:\\Windows\\System32",
  "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": "C:\\Windows\\SysWOW64",
  "724EF170-A42D-4FEF-9F26-B60E846FBA4F": "C:\\Users\\<계정>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
  "D0384E7D-BAC3-4797-8F14-CBA229B392B5": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
  // 사용자 폴더
  "5E6C858F-0E22-4760-9AFE-EA3317B67173": "C:\\Users\\<계정>",
  "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "C:\\Users\\<계정>\\Desktop",
  "FDD39AD0-238F-46AF-ADB4-6C85480369C7": "C:\\Users\\<계정>\\Documents",
  "374DE290-123F-4565-9164-39C4925E467B": "C:\\Users\\<계정>\\Downloads",
  "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": "C:\\Users\\<계정>\\AppData\\Local",
  "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": "C:\\Users\\<계정>\\AppData\\Roaming",
  "8983036C-27C0-404B-8F08-102D10DCFD74": "C:\\Users\\<계정>\\AppData\\Roaming\\Microsoft\\Windows\\SendTo",
  // 공용
  "DFDF76A2-C82A-4D63-906A-5644AC457385": "C:\\Users\\Public",
  "ED4824AF-DCE4-45A8-81E2-FC7965083634": "C:\\Users\\Public\\Desktop",
  "3D644C9B-1FB8-4F30-9B45-F670235F79C0": "C:\\Users\\Public\\Downloads",
};

const LEADING_GUID = /^\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}(?=\\|$)/;

/** 경로 맨 앞의 KNOWNFOLDERID GUID를 실제 경로로 바꾼다. 매핑이 없거나
 * GUID로 시작하지 않으면 null. */
export function resolveKnownFolderPath(path: string | undefined): string | null {
  if (!path) return null;
  const match = LEADING_GUID.exec(path.trim());
  if (!match) return null;
  const mapped = KNOWN_FOLDER_PATHS[match[1].toUpperCase()];
  if (!mapped) return null;
  return mapped + path.trim().slice(match[0].length);
}
