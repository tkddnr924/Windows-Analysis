// Microsoft Defender activity helpers (docs-13). Items follow stored groups
// (DefenderDetectionMembers detection_key, DefenderScans scan events); rows
// without a stored group stay single (R04). Sibling imports carry `.ts` for Node tests.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { facetAllows, groupEvents, type EventGroup } from "./eventOrder.ts";

type Cells = Record<string, string | undefined>;

export interface DefenderFilter {
  search: string;
  /** null = DEFAULT_SECTIONS; [] = all. */
  sections: string[] | null;
  severities: string[];
  categories: string[];
  results: string[];
}

// Initial view: detections and their actions only (user decision 2026-10-13).
export const DEFAULT_SECTIONS = ["threat", "threat_action"];
export const DEFAULT_DEFENDER_FILTER: DefenderFilter = { search: "", sections: null, severities: [], categories: [], results: [] };

export function selectedSections(filter: DefenderFilter, present: string[]): string[] {
  if (!filter.sections) return present.filter((section) => DEFAULT_SECTIONS.includes(section));
  return filter.sections.length ? filter.sections : present;
}

export type ItemKind = "detection" | "scan" | "record";
export interface ItemRef { key: string; kind: ItemKind }

/** record_id → stored group (detection first, then scan). */
export function groupIndex(members: Cells[], scans: Cells[]): Map<string, ItemRef> {
  const index = new Map<string, ItemRef>();
  for (const scan of scans) {
    for (const column of ["start_record_id", "completion_record_id", "cancel_record_id", "error_record_id"]) {
      const id = scan[column];
      if (id && scan.scan_entry_id) index.set(id, { key: scan.scan_entry_id, kind: "scan" });
    }
  }
  for (const member of members) {
    if (member.record_id && member.detection_key) index.set(member.record_id, { key: member.detection_key, kind: "detection" });
  }
  return index;
}

function matches(row: Cells, filter: DefenderFilter, sections: Set<string>): boolean {
  if (!sections.has(row.section ?? "") || !facetAllows(filter.severities, row.severity) || !facetAllows(filter.categories, row.category) || !facetAllows(filter.results, row.result)) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.threat_name, row.target_path, row.title, row.detail, row.process, row.account, row.account_sid].some((value) => (value ?? "").toLowerCase().includes(needle));
}

export interface DefenderItem<R extends Cells> extends EventGroup<R> {
  kind: ItemKind;
}

/** Time order (direction), untimed last, ties by record_id (R17). */
export function buildDefenderItems<R extends Cells>(rows: R[], index: Map<string, ItemRef>, filter: DefenderFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): DefenderItem<R>[] {
  const present = [...new Set(rows.map((row) => row.section ?? ""))];
  const sections = new Set(selectedSections(filter, present));
  const refOf = (row: R): ItemRef => index.get(row.record_id ?? "") ?? { key: `record::${row.record_id}`, kind: "record" };
  return groupEvents<R, DefenderItem<R>>(rows, {
    inPeriod,
    periodSet,
    direction,
    keyOf: (row) => refOf(row).key,
    create: (key, row) => ({ key, kind: refOf(row).kind, events: [], matched: new Set() }),
    matches: (row) => matches(row, filter, sections),
  });
}

export interface ProtectionLatest {
  feature: string;
  /** null when same-time observations disagree (R02). */
  state: string | null;
  time: string;
  tie: number;
  /** Decided (on/off) observations in the period. */
  count: number;
  first: string;
  recordId: string;
}

/** Last on/off observation per feature within the period (R02, A04). */
export function latestProtection(states: Cells[], inPeriod: (timestamp: string) => boolean): ProtectionLatest[] {
  const byFeature = new Map<string, Cells[]>();
  for (const row of states) {
    if (row.state !== "on" && row.state !== "off") continue;
    // Untimed observations cannot be the latest.
    if (!row.timestamp || !inPeriod(row.timestamp)) continue;
    byFeature.set(row.feature ?? "", [...(byFeature.get(row.feature ?? "") ?? []), row]);
  }
  const result: ProtectionLatest[] = [];
  for (const [feature, list] of byFeature) {
    // Same order as the stored Rust rule: time, then observation_ordinal.
    list.sort((a, b) => (a.timestamp ?? "").localeCompare(b.timestamp ?? "") || Number(a.observation_ordinal ?? 0) - Number(b.observation_ordinal ?? 0));
    const last = list[list.length - 1];
    const atTime = list.filter((row) => row.timestamp === last.timestamp);
    const conflict = atTime.some((row) => row.state !== atTime[0].state);
    result.push({ feature, state: conflict ? null : last.state ?? null, time: last.timestamp ?? "", tie: atTime.length, count: list.length, first: list[0].timestamp ?? "", recordId: conflict ? "" : last.record_id ?? "" });
  }
  return result;
}

export interface ActivitySummary {
  scan: { started: number; completed: number; cancelled: number; failed: number; last: string };
  signature: { updated: number; failed: number; version: string; last: string };
  history: { count: number; last: string };
  config: { count: number; exclusionsAdded: number; exclusionsRemoved: number; last: string };
}

/** In-period counts behind the one-line summaries (R06). */
export function summarizeActivity(rows: Cells[], inPeriod: (timestamp: string) => boolean, periodSet: boolean): ActivitySummary {
  const summary: ActivitySummary = {
    scan: { started: 0, completed: 0, cancelled: 0, failed: 0, last: "" },
    signature: { updated: 0, failed: 0, version: "", last: "" },
    history: { count: 0, last: "" },
    config: { count: 0, exclusionsAdded: 0, exclusionsRemoved: 0, last: "" },
  };
  let versionTime = "";
  const later = (current: string, time: string) => (time > current ? time : current);
  for (const row of rows) {
    const time = row.timestamp ?? "";
    if (time ? !inPeriod(time) : periodSet) continue;
    if (row.section === "scan") {
      if (row.event_type === "scan_started") summary.scan.started += 1;
      else if (row.event_type === "scan_completed") summary.scan.completed += 1;
      else if (row.event_type === "scan_cancelled") summary.scan.cancelled += 1;
      else if (row.event_type === "scan_error") summary.scan.failed += 1;
      summary.scan.last = later(summary.scan.last, time);
    } else if (row.section === "signature") {
      if (row.result === "failure") summary.signature.failed += 1;
      else summary.signature.updated += 1;
      if (row.signature_version_current && time >= versionTime) { versionTime = time; summary.signature.version = row.signature_version_current; }
      summary.signature.last = later(summary.signature.last, time);
    } else if (row.section === "history") {
      summary.history.count += 1;
      summary.history.last = later(summary.history.last, time);
    } else if (row.event_type === "configuration_changed") {
      summary.config.count += 1;
      if (row.config_exclusion_kind && row.config_change_kind === "added") summary.config.exclusionsAdded += 1;
      if (row.config_exclusion_kind && row.config_change_kind === "removed") summary.config.exclusionsRemoved += 1;
      summary.config.last = later(summary.config.last, time);
    }
  }
  return summary;
}

export const RESULT_LABELS: Record<string, string> = { success: "성공", failure: "실패", blocked: "차단", audited: "감사", warn_overridden: "경고 무시", unknown: "미확정" };
export const FEATURE_LABELS: Record<string, string> = { realtime_protection: "실시간 보호", on_access: "액세스 시 검사", ioav: "다운로드 검사", behavior_monitoring: "동작 모니터링", malware_scanning: "맬웨어 검사", virus_scanning: "바이러스 검사" };
export const CHANGE_LABELS: Record<string, string> = { added: "추가", removed: "삭제", changed: "변경" };
export const EXCLUSION_LABELS: Record<string, string> = { Paths: "경로", Extensions: "확장자", Processes: "프로세스", IpAddresses: "IP 주소" };
