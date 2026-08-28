// Small helpers shared verbatim by several views. Each was previously
// duplicated per-component; behavior is unchanged.
import type { CSSProperties } from "react";

/// True when `fullPath` sits at or below the host output directory.
export function pathBelongsToHost(fullPath: string, hostDir: string): boolean {
  const path = fullPath.replace(/\\/g, "/").replace(/\/+$/, "");
  const root = hostDir.replace(/\\/g, "/").replace(/\/+$/, "");
  return path === root || path.startsWith(`${root}/`);
}

// Providers report the account differently — bare "Administrator" from
// TerminalServices, "HOST\Administrator" from Security-Auditing. Strip any
// DOMAIN\/HOST\ prefix (and UPN @suffix) so the same user reads consistently.
export function bareAccount(name: string): string {
  if (!name) return "";
  const tail = name.replace(/\//g, "\\").split("\\").pop() ?? name;
  return tail.split("@")[0].trim();
}

/// "YYYY-MM-DD HH:MM:SS" (KST text) -> epoch ms, NaN when empty.
export function tsMs(timestamp: string): number {
  return timestamp ? new Date(timestamp.replace(" ", "T")).getTime() : Number.NaN;
}

/// Last path segment of a Windows or POSIX path ("" stays "").
export function basename(path: string): string {
  const clean = (path || "").replace(/[\\/]+$/, "");
  return clean.split(/[\\/]/).at(-1) || path;
}

/// Screen-reader-only text (standard visually-hidden pattern).
export const visuallyHidden: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0, 0, 0, 0)",
  whiteSpace: "nowrap",
  border: 0,
};
