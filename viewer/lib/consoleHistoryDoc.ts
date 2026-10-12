// PSReadLine history as one read-only document. No runtime imports (Node tests).

export interface ConsoleDoc {
  text: string;
  /** Original ConsoleHost_history line per document line; null when unknown. */
  sourceLines: (number | null)[];
}

export function buildConsoleDoc(rows: { line_number?: string | null; command?: string | null }[]): ConsoleDoc {
  const parts: string[] = [];
  const sourceLines: (number | null)[] = [];
  for (const row of rows) {
    const command = row.command ?? "";
    const start = Number.parseInt(row.line_number ?? "", 10);
    const lineCount = command.split("\n").length;
    for (let offset = 0; offset < lineCount; offset += 1) sourceLines.push(Number.isFinite(start) ? start + offset : null);
    parts.push(command);
  }
  return { text: parts.join("\n"), sourceLines };
}

/** Literal, case-insensitive, non-overlapping matches (offsets into `text`). */
export function findMatches(text: string, query: string): { from: number; to: number }[] {
  if (!query) return [];
  // A regex keeps offsets exact; lowercasing can change string length.
  const pattern = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "giu");
  return [...text.matchAll(pattern)].map((match) => ({ from: match.index, to: match.index + match[0].length }));
}
