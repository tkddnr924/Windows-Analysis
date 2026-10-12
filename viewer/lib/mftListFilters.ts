// Recursive file list filters (docs-04 §3) as one UI state, mapped to the
// mft_records_page options. Type-only imports (Node tests run this file).
import type { MftListOptions } from "./types";

// SI and FN time fields (key = mft_records_page time/sort key), canonical order.
export const MFT_TIME_FIELDS: Record<string, { label: string; short: string; column: string }> = {
  created: { label: "생성 시각", short: "SI 생성", column: "si_created" },
  modified: { label: "수정 시각", short: "SI 수정", column: "si_modified" },
  mft_modified: { label: "MFT 수정 시각", short: "SI MFT 수정", column: "si_mft_modified" },
  accessed: { label: "접근 시각", short: "SI 접근", column: "si_accessed" },
  fn_created: { label: "생성 시각 ($FN)", short: "FN 생성", column: "fn_created" },
  fn_modified: { label: "수정 시각 ($FN)", short: "FN 수정", column: "fn_modified" },
  fn_mft_modified: { label: "MFT 수정 시각 ($FN)", short: "FN MFT 수정", column: "fn_mft_modified" },
  fn_accessed: { label: "접근 시각 ($FN)", short: "FN 접근", column: "fn_accessed" },
};
const TIME_ORDER = Object.keys(MFT_TIME_FIELDS);

export type SizePreset = "all" | "small" | "kb" | "mb" | "large";
/** all · range(from and/or to) · around(anchor − before … anchor + after). */
export type TimeMode = "all" | "range" | "around";

export interface ListFilters {
  sortKey: string;
  sortDesc: boolean;
  kind: "file" | "dir" | "all";
  inUse: "all" | "1" | "0";
  extension: string;
  pattern: string;
  pathPrefix: string;
  excludePaths: string[];
  size: SizePreset;
  pathIncomplete: boolean;
  residentOnly: boolean;
  siBeforeFn: boolean;
  /** Period fields; a record matches when ANY of them is in range. */
  timeKeys: string[];
  timeMode: TimeMode;
  timeFrom: string;
  timeTo: string;
  anchor: string;
  /** Minutes before / after the anchor. */
  aroundBefore: number;
  aroundAfter: number;
}

export const DEFAULT_LIST_FILTERS: ListFilters = {
  sortKey: "path",
  sortDesc: false,
  kind: "file",
  inUse: "all",
  extension: "",
  pattern: "",
  pathPrefix: "",
  excludePaths: [],
  size: "all",
  pathIncomplete: false,
  residentOnly: false,
  siBeforeFn: false,
  timeKeys: ["created", "fn_created"],
  timeMode: "all",
  timeFrom: "",
  timeTo: "",
  anchor: "",
  aroundBefore: 30,
  aroundAfter: 30,
};

export const AROUND_PRESETS: { minutes: number; label: string }[] = [
  { minutes: 1, label: "1분" },
  { minutes: 5, label: "5분" },
  { minutes: 10, label: "10분" },
  { minutes: 30, label: "30분" },
  { minutes: 60, label: "1시간" },
  { minutes: 360, label: "6시간" },
  { minutes: 1440, label: "1일" },
];

/** What happened in the window: created, modified, or either (SI, plus FN when asked). */
export type Activity = "created" | "modified" | "both";
const ACTIVITY_KEYS: Record<Activity, string[]> = { created: ["created"], modified: ["modified"], both: ["created", "modified"] };

export function timeKeysFor(activity: Activity, withFn: boolean): string[] {
  const si = ACTIVITY_KEYS[activity];
  return withFn ? [...si, ...si.map((key) => `fn_${key}`)] : [...si];
}

/** Inverse of timeKeysFor; null for a hand-picked set. */
export function activityOf(keys: string[]): { activity: Activity; withFn: boolean } | null {
  for (const activity of Object.keys(ACTIVITY_KEYS) as Activity[]) {
    for (const withFn of [false, true]) {
      const expected = timeKeysFor(activity, withFn);
      if (expected.length === keys.length && expected.every((key) => keys.includes(key))) return { activity, withFn };
    }
  }
  return null;
}

// Windows servicing stores (component store, update staging): they change
// in bulk on every update and bury other activity in a time window.
export const NOISE_FOLDERS = ["\\Windows\\WinSxS", "\\Windows\\servicing", "\\Windows\\SoftwareDistribution"];

export function noiseExcluded(filters: ListFilters): boolean {
  return NOISE_FOLDERS.every((path) => filters.excludePaths.includes(path));
}

export function withNoiseExcluded(filters: ListFilters, on: boolean): ListFilters {
  const rest = filters.excludePaths.filter((path) => !NOISE_FOLDERS.includes(path));
  return { ...filters, excludePaths: on ? [...rest, ...NOISE_FOLDERS] : rest };
}

const KB = 1024;
const MB = 1024 * KB;
export const SIZE_PRESETS: Record<SizePreset, { label: string; min?: number; max?: number }> = {
  all: { label: "전체" },
  small: { label: "≤ 1 KB", min: 0, max: KB },
  kb: { label: "1 KB – 1 MB", min: KB + 1, max: MB },
  mb: { label: "1 MB – 100 MB", min: MB + 1, max: 100 * MB },
  large: { label: "≥ 100 MB", min: 100 * MB },
};

// Analyst shortcuts: they only fill the extension filter (visible and editable).
export const EXTENSION_PRESETS = {
  executable: { label: "실행·스크립트", extensions: ["exe", "dll", "sys", "scr", "msi", "ps1", "psm1", "bat", "cmd", "vbs", "js", "jse", "hta", "lnk", "jar"] },
  document: { label: "문서", extensions: ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv", "rtf", "hwp", "hwpx"] },
  archive: { label: "압축", extensions: ["zip", "7z", "rar", "gz", "tar", "cab", "iso", "tgz", "xz"] },
} as const;
export type ExtensionPreset = keyof typeof EXTENSION_PRESETS;

function extensionSet(value: string): Set<string> {
  return new Set(value.split(/[\s,]+/).map((part) => part.trim().replace(/^\./, "").toLowerCase()).filter(Boolean));
}

export function presetActive(filters: ListFilters, preset: ExtensionPreset): boolean {
  const current = extensionSet(filters.extension);
  const expected = EXTENSION_PRESETS[preset].extensions;
  return current.size === expected.length && expected.every((extension) => current.has(extension));
}

function cleanExcludes(paths: string[]): string[] {
  return [...new Set(paths.map((path) => path.trim()).filter(Boolean))];
}

const TIME_PATTERN = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?$/;

interface Parsed { y: number; mo: number; d: number; hh?: number; mm?: number; ss?: number; ms?: string }

/** Strict parse: the calendar date and clock must exist as typed. */
function parse(value: string): Parsed | null {
  const m = value.trim().match(TIME_PATTERN);
  if (!m) return null;
  const [, y, mo, d, hh, mm, ss, ms] = m;
  const p: Parsed = { y: +y, mo: +mo, d: +d, hh: hh === undefined ? undefined : +hh, mm: mm === undefined ? undefined : +mm, ss: ss === undefined ? undefined : +ss, ms };
  const date = new Date(Date.UTC(p.y, p.mo - 1, p.d));
  if (date.getUTCFullYear() !== p.y || date.getUTCMonth() !== p.mo - 1 || date.getUTCDate() !== p.d) return null;
  if ((p.hh ?? 0) > 23 || (p.mm ?? 0) > 59 || (p.ss ?? 0) > 59) return null;
  return p;
}

const pad = (n: number, w = 2) => String(n).padStart(w, "0");

/** Partial input → stored-format bound ("YYYY-MM-DD HH:MM:SS.mmm"). */
function expand(p: Parsed, edge: "start" | "end"): string {
  const floor = edge === "start";
  const fraction = p.ms ? p.ms.padEnd(3, floor ? "0" : "9") : floor ? "000" : "999";
  const hh = p.hh ?? (floor ? 0 : 23);
  const mm = p.mm ?? (floor ? 0 : 59);
  const ss = p.ss ?? (floor ? 0 : 59);
  return `${p.y}-${pad(p.mo)}-${pad(p.d)} ${pad(hh)}:${pad(mm)}:${pad(ss)}.${fraction}`;
}

/** Shift by minutes; wall-clock arithmetic on the stored (KST) text, no zone. */
function shift(p: Parsed, minutes: number): string {
  const t = new Date(Date.UTC(p.y, p.mo - 1, p.d, p.hh ?? 0, p.mm ?? 0, p.ss ?? 0, +(p.ms ?? "0").padEnd(3, "0")) + minutes * 60_000);
  return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())} ${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}:${pad(t.getUTCSeconds())}.${pad(t.getUTCMilliseconds(), 3)}`;
}

export type TimeBounds = { start?: string; end?: string; error?: string };

/** Inclusive period on the chosen fields. Input that is not a real time, or a
 *  reversed range, is an error with no bounds — never a different period. */
export function timeBounds(filters: ListFilters): TimeBounds {
  const read = (value: string, what: string): Parsed | string => {
    if (!value.trim()) return `${what}을 입력하세요`;
    return parse(value) ?? `${what} "${value.trim()}"은(는) 존재하지 않는 날짜·시각입니다 (YYYY-MM-DD HH:MM:SS)`;
  };
  switch (filters.timeMode) {
    case "all":
      return {};
    case "range": {
      // Start only = after, end only = before, both = between.
      const hasFrom = Boolean(filters.timeFrom.trim());
      const hasTo = Boolean(filters.timeTo.trim());
      if (!hasFrom && !hasTo) return { error: "시작 또는 끝 시각을 입력하세요" };
      const from = hasFrom ? read(filters.timeFrom, "시작 시각") : null;
      if (typeof from === "string") return { error: from };
      const to = hasTo ? read(filters.timeTo, "끝 시각") : null;
      if (typeof to === "string") return { error: to };
      const start = from ? expand(from, "start") : undefined;
      const end = to ? expand(to, "end") : undefined;
      if (start && end && start > end) return { error: "시작 시각이 끝 시각보다 늦습니다" };
      return { ...(start ? { start } : {}), ...(end ? { end } : {}) };
    }
    case "around": {
      const anchor = read(filters.anchor, "기준 시각");
      if (typeof anchor === "string") return { error: anchor };
      return { start: shift(anchor, -Math.max(0, filters.aroundBefore)), end: shift(anchor, Math.max(0, filters.aroundAfter)) };
    }
  }
}

const isTimeSort = (key: string) => key in MFT_TIME_FIELDS;

/** Select period fields (canonical order, at least one). A sort that followed
 *  a time field follows the first selected one. */
export function withTimeKeys(filters: ListFilters, keys: string[]): ListFilters {
  const timeKeys = TIME_ORDER.filter((key) => keys.includes(key));
  if (!timeKeys.length) return filters;
  const followSort = isTimeSort(filters.sortKey) && !timeKeys.includes(filters.sortKey);
  return { ...filters, timeKeys, ...(followSort ? { sortKey: timeKeys[0] } : {}) };
}

/** Choosing a time window lists records in time order, unless the analyst
 *  already picked a non-default sort. */
export function withTimeMode(filters: ListFilters, timeMode: TimeMode): ListFilters {
  const followSort = timeMode !== "all" && filters.sortKey === DEFAULT_LIST_FILTERS.sortKey;
  return { ...filters, timeMode, ...(followSort ? { sortKey: filters.timeKeys[0], sortDesc: false } : {}) };
}

const ACTIVITY_LABELS: Record<Activity, string> = { created: "생성", modified: "수정", both: "생성·수정" };

export function timeFieldsLabel(keys: string[]): string {
  const known = activityOf(keys);
  if (known) return `${ACTIVITY_LABELS[known.activity]} (${known.withFn ? "SI·FN" : "SI"})`;
  return keys.map((key) => MFT_TIME_FIELDS[key]?.short ?? key).join("·");
}

function timeSummary(filters: ListFilters): string | null {
  const bounds = timeBounds(filters);
  if (!bounds.start && !bounds.end) return null;
  const fields = timeFieldsLabel(filters.timeKeys);
  const fmt = (minutes: number) => AROUND_PRESETS.find((p) => p.minutes === minutes)?.label ?? `${minutes}분`;
  if (filters.timeMode === "around") return `${fields}: ${filters.anchor.trim()} 앞 ${fmt(filters.aroundBefore)} · 뒤 ${fmt(filters.aroundAfter)}`;
  if (bounds.start && bounds.end) return `${fields}: ${filters.timeFrom.trim()} ~ ${filters.timeTo.trim()}`;
  return bounds.start ? `${fields}: ${filters.timeFrom.trim()} 이후` : `${fields}: ${filters.timeTo.trim()} 이전`;
}

/** Human-readable active conditions (toolbar summary, modal footer). */
export function describeFilters(filters: ListFilters): string[] {
  const out: string[] = [];
  const time = timeSummary(filters);
  if (time) out.push(time);
  if (filters.kind !== DEFAULT_LIST_FILTERS.kind) out.push(filters.kind === "dir" ? "폴더만" : "파일·폴더");
  if (filters.inUse !== "all") out.push(filters.inUse === "1" ? "사용 중 레코드" : "비사용 레코드");
  if (filters.pathPrefix.trim()) out.push(`폴더: ${filters.pathPrefix.trim()}`);
  const noise = noiseExcluded(filters);
  if (noise) out.push("Windows 업데이트 폴더 제외");
  for (const path of cleanExcludes(filters.excludePaths)) if (!(noise && NOISE_FOLDERS.includes(path))) out.push(`제외: ${path}`);
  if (filters.pattern.trim()) out.push(`이름: ${filters.pattern.trim()}`);
  if (filters.extension.trim()) {
    const preset = (Object.keys(EXTENSION_PRESETS) as ExtensionPreset[]).find((key) => presetActive(filters, key));
    out.push(`확장자: ${preset ? EXTENSION_PRESETS[preset].label : filters.extension.trim()}`);
  }
  if (filters.size !== "all") out.push(`크기 ${SIZE_PRESETS[filters.size].label}`);
  if (filters.pathIncomplete) out.push("경로 불완전");
  if (filters.residentOnly) out.push("Resident");
  if (filters.siBeforeFn) out.push("SI 생성 < FN 생성");
  return out;
}

/** Conditions that narrow the result (sort excluded). */
export function activeFilterCount(filters: ListFilters): number {
  return describeFilters(filters).length;
}

/** IPC options for mft_records_page. Invalid time input sends no bounds (the
 *  dialog blocks applying it). */
export function toListOptions(filters: ListFilters, volumeId: string | undefined): MftListOptions {
  const size = SIZE_PRESETS[filters.size];
  const bounds = timeBounds(filters);
  const timed = Boolean(bounds.start || bounds.end);
  const excludes = cleanExcludes(filters.excludePaths);
  const options: MftListOptions = {
    sortKey: filters.sortKey,
    sortDesc: filters.sortDesc,
    kind: filters.kind === "all" ? undefined : filters.kind,
    inUse: filters.inUse === "all" ? undefined : Number(filters.inUse),
    extension: filters.extension.trim() || undefined,
    namePattern: filters.pattern.trim() || undefined,
    pathPrefix: filters.pathPrefix.trim() || undefined,
    excludePaths: excludes.length ? excludes : undefined,
    sizeMin: size.min,
    sizeMax: size.max,
    pathIncomplete: filters.pathIncomplete || undefined,
    residentOnly: filters.residentOnly || undefined,
    siBeforeFn: filters.siBeforeFn || undefined,
    timeKeys: timed ? filters.timeKeys : undefined,
    timeStart: bounds.start,
    timeEnd: bounds.end,
    volumeId,
  };
  // Drop unset keys so the IPC payload and summaries stay minimal.
  for (const key of Object.keys(options) as (keyof MftListOptions)[]) if (options[key] === undefined) delete options[key];
  return options;
}
