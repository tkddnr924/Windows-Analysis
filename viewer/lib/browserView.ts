// Browser activity / AI conversation helpers (docs-07). Labels map stored
// enumerated values only; nothing is inferred. No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

interface InputLike {
  inputId: string;
  inputKind: string;
  browser: string | null;
  profile: string | null;
  accountLabel: string | null;
  account: string | null;
  accountSid: string | null;
  recordCount: number;
}

export interface BrowserScope {
  key: string;
  /** "Chrome · Default" */
  label: string;
  /** Collected account label (not a confirmed Windows account). */
  owner: string | null;
  /** Confirmed account/SID only when every input agrees. */
  account: string | null;
  accountSid: string | null;
  inputIds: string[];
  inputKinds: string[];
  recordCount: number;
}

/** One scope per browser + profile + collected label (history and cache together). */
export function browserScopes(inputs: InputLike[]): BrowserScope[] {
  const scopes = new Map<string, BrowserScope>();
  for (const input of inputs) {
    const key = [input.browser ?? "", input.profile ?? "", input.accountLabel ?? ""].join("\u0000");
    const scope = scopes.get(key);
    if (!scope) {
      scopes.set(key, {
        key,
        label: [input.browser || "(브라우저 미상)", input.profile].filter(Boolean).join(" · "),
        owner: input.accountLabel,
        account: input.account,
        accountSid: input.accountSid,
        inputIds: [input.inputId],
        inputKinds: [input.inputKind],
        recordCount: input.recordCount,
      });
      continue;
    }
    scope.inputIds.push(input.inputId);
    if (!scope.inputKinds.includes(input.inputKind)) scope.inputKinds.push(input.inputKind);
    scope.recordCount += input.recordCount;
    if (scope.account !== input.account) scope.account = null;
    if (scope.accountSid !== input.accountSid) scope.accountSid = null;
  }
  return [...scopes.values()];
}

export const KIND_LABELS: Record<string, string> = { visit: "방문", url_summary: "URL 요약", download: "다운로드", cache: "캐시" };

// Chromium page transition names stored by the parser (ui/base/page_transition_types.h).
const TRANSITION_CORE: Record<string, string> = {
  LINK: "링크 클릭",
  TYPED: "주소창 직접 입력",
  AUTO_BOOKMARK: "북마크",
  AUTO_SUBFRAME: "자동 하위 프레임",
  MANUAL_SUBFRAME: "수동 하위 프레임",
  GENERATED: "주소창 추천 이동",
  START_PAGE: "시작 페이지",
  FORM_SUBMIT: "폼 제출",
  RELOAD: "새로고침",
  KEYWORD: "키워드 검색",
  KEYWORD_GENERATED: "키워드 생성",
};
const TRANSITION_QUALIFIER: Record<string, string> = {
  BLOCKED: "차단",
  FORWARD_BACK: "앞/뒤 이동",
  FROM_ADDRESS_BAR: "주소창",
  HOME_PAGE: "홈 페이지",
  FROM_API: "API",
  CHAIN_START: "체인 시작",
  CHAIN_END: "체인 끝",
  CLIENT_REDIRECT: "클라이언트 리다이렉트",
  SERVER_REDIRECT: "서버 리다이렉트",
};

export function transitionLabel(core: string | undefined, qualifiers: string | undefined): string {
  const head = core ? TRANSITION_CORE[core] ?? core : "";
  const tail = (qualifiers ?? "").split(",").map((value) => value.trim()).filter(Boolean).map((value) => TRANSITION_QUALIFIER[value] ?? value);
  return [head, tail.join(", ")].filter(Boolean).join(" · ");
}

// history::DownloadState (components/history/core/browser/download_constants.h).
const DOWNLOAD_STATE: Record<string, string> = { "0": "진행 중", "1": "완료", "2": "취소", "4": "중단" };

export function downloadStateLabel(raw: string | undefined): string {
  return raw ? DOWNLOAD_STATE[raw] ?? raw : "";
}

type MessageLike = Cells & { ordinal?: string; on_current_branch?: string; branch_ordinal?: string };

const num = (value: string | undefined) => (value === undefined || value === "" ? Number.POSITIVE_INFINITY : Number(value));

/**
 * `current`: messages on the stored current branch in branch order; when no
 * message carries branch evidence, every message in stored order.
 * `all`: every message in stored order, off-branch ones marked.
 */
export function messageThread<T extends MessageLike>(messages: T[], mode: "current" | "all"): (T & { offBranch: boolean })[] {
  const ordered = [...messages].sort((left, right) => num(left.ordinal) - num(right.ordinal));
  const known = ordered.some((message) => message.on_current_branch === "1" || message.on_current_branch === "0");
  const marked = ordered.map((message) => ({ ...message, offBranch: message.on_current_branch === "0" }));
  if (mode === "all" || !known) return marked;
  return marked
    .filter((message) => message.on_current_branch === "1")
    .sort((left, right) => num(left.branch_ordinal) - num(right.branch_ordinal) || num(left.ordinal) - num(right.ordinal));
}

/** Attachments keyed by `message_ordinal` ("" when not linked to a message). */
export function attachmentsByMessage<T extends Cells>(attachments: T[]): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const attachment of attachments) {
    const key = attachment.message_ordinal ?? "";
    groups.set(key, [...(groups.get(key) ?? []), attachment]);
  }
  return groups;
}

/** Declared image/text types first; otherwise text only when it is strict UTF-8 without NUL. */
export function bodyKind(bytes: Uint8Array, contentType: string | undefined): "image" | "text" | "binary" {
  const type = (contentType ?? "").toLowerCase();
  if (type.startsWith("image/") && !type.includes("svg")) return "image";
  if (type.startsWith("text/") || /json|javascript|xml|svg|x-www-form-urlencoded/.test(type)) return "text";
  if (bytes.includes(0)) return "binary";
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return "text";
  } catch {
    return "binary";
  }
}
