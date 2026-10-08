import type { ResultFileEntry } from "./types";

/**
 * Under the storage contract (docs-01) each result DB has exactly one
 * analyst-facing table (named after the file); the rest hold detail and
 * evidence for its rows. Listing, search and the timeline must not offer those
 * as browsable tables. The backend applies the same rule; this is the second
 * guard so a detail-only table never reaches the UI from an older publish.
 */
export const DETAIL_ONLY_TABLES: Record<string, true> = {
  source_records: true,
  ExecutionTimes: true,
  ExecutionVolumes: true,
  AiMessages: true,
  AiAttachments: true,
  TaskActions: true,
  TaskTriggers: true,
  BitsFiles: true,
  MetadataAddresses: true,
  MetadataGateways: true,
  MetadataDnsServers: true,
  MetadataGroups: true,
  MetadataCandidates: true,
};

/** Keeps only tables an analyst opens directly; detail tables load per row. */
export function browsableResultFiles(files: ResultFileEntry[]): ResultFileEntry[] {
  return files.filter((file) => !DETAIL_ONLY_TABLES[file.tableName]);
}

/**
 * Host folder of a result path `<hostDir>/<CATEGORY>/<file>.sqlite`.
 * source_records store source_db relative to that folder.
 */
export function hostDirOfResultPath(fullPath: string): string {
  const parts = fullPath.split(/[\\/]/);
  return parts.slice(0, Math.max(0, parts.length - 2)).join("/");
}
