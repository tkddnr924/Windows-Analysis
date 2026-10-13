// Indented JSON for object/array text; null for anything else.
export function prettyJsonOrNull(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

// Expands literal \r\n, \n, \t into real whitespace for display.
// Escaped backslash pairs (e.g. "C:\\Windows") are kept verbatim.
export function unescapeControlSequences(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = text[i + 1];
    if (next === "\\") {
      out += "\\\\";
      i += 1;
      continue;
    }
    if (next === "r") {
      // \r\n collapses to one line break.
      if (text[i + 2] === "\\" && text[i + 3] === "n") i += 2;
      out += "\n";
      i += 1;
      continue;
    }
    if (next === "n") {
      out += "\n";
      i += 1;
      continue;
    }
    if (next === "t") {
      out += "    ";
      i += 1;
      continue;
    }
    out += ch;
  }
  return out;
}

export function hasControlSequences(text: string): boolean {
  return unescapeControlSequences(text) !== text;
}
