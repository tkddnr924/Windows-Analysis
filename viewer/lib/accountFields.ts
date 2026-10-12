// Display mapping for metadata account columns (docs viewer-03). No runtime
// imports: tests run on Node directly.

/** metadata 0/1 flags: 1 → 예, 0 → 아니오, NULL/other → "" (unknown). */
export function yesNo(value: string | null | undefined): string {
  return value === "1" ? "예" : value === "0" ? "아니오" : "";
}

/** ACB flag names stored in details_json.acb_flags, joined for display. */
export function acbFlagNames(detailsJson: string | null | undefined): string {
  try {
    const flags = JSON.parse(detailsJson || "{}").acb_flags;
    return Array.isArray(flags) ? flags.join(", ") : "";
  } catch {
    return "";
  }
}
