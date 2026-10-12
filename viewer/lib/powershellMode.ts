import type { StreamParser, StringStream } from "@codemirror/language";

// Minimal PowerShell colouring for history lines. The legacy CodeMirror mode
// tags commands, arguments and $variables alike, so it cannot tell them apart.

const KEYWORDS = /^(?:begin|break|catch|class|continue|data|do|dynamicparam|else|elseif|end|exit|filter|finally|for|foreach|function|if|in|param|process|return|switch|throw|trap|try|until|while)$/i;

interface State {
  /** Next word is a command (line start, after | ; { ( && ||). */
  command: boolean;
  /** Open construct carried to the next line. */
  open: null | { kind: "string"; quote: string } | { kind: "here"; quote: string } | { kind: "comment" };
}

// Reads a quoted string body up to its closing quote; true when closed.
function readString(stream: StringStream, quote: string): boolean {
  let escaped = false;
  while (!stream.eol()) {
    const next = stream.next();
    if (next === quote && !escaped) return true;
    escaped = quote === "\"" && next === "`" && !escaped;
  }
  return false;
}

export const powershellMode: StreamParser<State> = {
  name: "powershell-history",
  startState: () => ({ command: true, open: null }),
  copyState: (state) => ({ command: state.command, open: state.open && { ...state.open } }),
  token(stream, state) {
    const open = state.open;
    if (open?.kind === "here") {
      // Here-string ends only with `"@` / `'@` at line start.
      if (stream.sol() && stream.match(`${open.quote}@`)) {
        state.open = null;
        state.command = false;
      } else {
        stream.skipToEnd();
      }
      return "string";
    }
    if (open?.kind === "comment") {
      if (stream.skipTo("#>")) {
        stream.pos += 2;
        state.open = null;
      } else {
        stream.skipToEnd();
      }
      return "comment";
    }
    if (open?.kind === "string") {
      if (readString(stream, open.quote)) state.open = null;
      return "string";
    }
    if (stream.sol()) state.command = true;
    if (stream.eatSpace()) return null;
    if (stream.match("<#")) {
      state.open = { kind: "comment" };
      if (stream.skipTo("#>")) {
        stream.pos += 2;
        state.open = null;
      } else {
        stream.skipToEnd();
      }
      return "comment";
    }
    const here = stream.match(/^@(["'])\s*$/);
    if (here) {
      state.open = { kind: "here", quote: (here as RegExpMatchArray)[1] };
      return "string";
    }
    const ch = stream.peek();
    if (ch === "#") {
      stream.skipToEnd();
      return "comment";
    }
    if (ch === "'" || ch === "\"") {
      stream.next();
      if (!readString(stream, ch)) state.open = { kind: "string", quote: ch };
      state.command = false;
      return "string";
    }
    if (stream.match(/^\$(?:\{[^}]*\}|[\w:?]+)/)) {
      state.command = false;
      return "variable-2";
    }
    if (stream.match(/^\[[A-Za-z_][\w.`,\[\] ]*\]/)) {
      state.command = false;
      return "type";
    }
    if (stream.match(/^(?:&&|\|\||[|;{(])/)) {
      state.command = true;
      return "operator";
    }
    if (stream.match(/^(?:::|[)}\],=+*%<>!&.:])/)) {
      state.command = false;
      return "operator";
    }
    if (!state.command && stream.match(/^-[A-Za-z][\w-]*/)) return "attribute";
    if (stream.match(/^-?\d+(?:\.\d+)?(?:[kmgtp]b)?(?![\w\\:.-])/i)) {
      state.command = false;
      return "number";
    }
    const word = stream.match(/^[^\s|;(){}\[\],'"#$=]+/);
    if (word) {
      const text = (word as RegExpMatchArray)[0];
      const wasCommand = state.command;
      state.command = false;
      if (KEYWORDS.test(text)) return "keyword";
      return wasCommand ? "builtin" : null;
    }
    stream.next();
    state.command = false;
    return null;
  },
};
