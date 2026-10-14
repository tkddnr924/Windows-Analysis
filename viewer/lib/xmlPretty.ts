// Indent stored XML text for reading. The stored value itself is never changed.

const TOKEN = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[A-Za-z_][^>"']*(?:(?:"[^"]*"|'[^']*')[^>"']*)*\/?>/g;

type Token =
  | { kind: "open" | "close"; name: string; text: string }
  | { kind: "self" | "other" | "text"; text: string };

function tokenize(raw: string): Token[] | null {
  const tokens: Token[] = [];
  let last = 0;
  for (const match of raw.matchAll(TOKEN)) {
    // Whitespace-only runs are separators; other text keeps every character.
    const between = raw.slice(last, match.index);
    if (between.trim()) tokens.push({ kind: "text", text: between });
    const text = match[0];
    if (text.startsWith("</")) tokens.push({ kind: "close", name: text.slice(2, -1).trim(), text });
    else if (text.startsWith("<!") || text.startsWith("<?")) tokens.push({ kind: "other", text });
    else if (text.endsWith("/>")) tokens.push({ kind: "self", text });
    else tokens.push({ kind: "open", name: /^<([^\s/>]+)/.exec(text)?.[1] ?? "", text });
    last = (match.index ?? 0) + text.length;
  }
  const tail = raw.slice(last);
  if (tail.trim()) tokens.push({ kind: "text", text: tail });
  return tokens;
}

/** Indented XML, or null when the text is not a balanced element-only XML
 * fragment. Mixed content and xml:space="preserve" stay raw. */
export function prettyXmlOrNull(raw: string): string | null {
  const source = raw.trim();
  if (!source.startsWith("<") || !source.endsWith(">")) return null;
  if (/xml:space\s*=\s*["']preserve["']/.test(source)) return null;
  const tokens = tokenize(source);
  if (!tokens?.some((token) => token.kind === "open" || token.kind === "self")) return null;
  const lines: string[] = [];
  const stack: string[] = [];
  const pad = () => "  ".repeat(stack.length);
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token.kind === "open") {
      const next = tokens[i + 1];
      const after = tokens[i + 2];
      // <a>text</a> and <a></a> stay on one line.
      if (next?.kind === "close" && next.name === token.name) {
        lines.push(pad() + token.text + next.text);
        i += 1;
        continue;
      }
      if (next?.kind === "text" && after?.kind === "close" && after.name === token.name) {
        lines.push(pad() + token.text + next.text + after.text);
        i += 2;
        continue;
      }
      lines.push(pad() + token.text);
      stack.push(token.name);
    } else if (token.kind === "close") {
      if (stack.pop() !== token.name) return null;
      lines.push(pad() + token.text);
    } else if (token.kind === "text") {
      // Text beside sibling elements is mixed content: re-indenting would alter it.
      return null;
    } else {
      lines.push(pad() + token.text);
    }
  }
  return stack.length === 0 ? lines.join("\n") : null;
}
