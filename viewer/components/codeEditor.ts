// Shared CodeMirror look and language loaders for read-only evidence viewers.
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from "@codemirror/language";
import { php } from "@codemirror/lang-php";
import { csharp } from "@codemirror/legacy-modes/mode/clike";
import { css } from "@codemirror/legacy-modes/mode/css";
import { javascript, json, typescript } from "@codemirror/legacy-modes/mode/javascript";
import { python } from "@codemirror/legacy-modes/mode/python";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { standardSQL } from "@codemirror/legacy-modes/mode/sql";
import { vbScript } from "@codemirror/legacy-modes/mode/vbscript";
import { html, xml } from "@codemirror/legacy-modes/mode/xml";
import { yaml } from "@codemirror/legacy-modes/mode/yaml";
import type { Extension } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { powershellMode } from "@/lib/powershellMode";
import type { CodeLanguageId } from "@/lib/codeLanguage";

const highlight = HighlightStyle.define([
  { tag: tags.keyword, color: "var(--accent)", fontWeight: "600" },
  { tag: [tags.standard(tags.variableName), tags.definition(tags.variableName)], color: "#eacb75" },
  { tag: [tags.attributeName, tags.propertyName], color: "#8fcaff" },
  { tag: tags.special(tags.variableName), color: "#b7b0ff" },
  { tag: [tags.typeName, tags.className], color: "#7fd1c7" },
  { tag: tags.tagName, color: "var(--accent)" },
  { tag: tags.string, color: "var(--success)" },
  { tag: [tags.number, tags.bool, tags.atom, tags.null], color: "#f0a36b" },
  { tag: [tags.comment, tags.meta], color: "var(--text-faint)", fontStyle: "italic" },
  { tag: [tags.operator, tags.angleBracket, tags.punctuation], color: "var(--text-dim)" },
]);

const theme = EditorView.theme({
  "&": { height: "100%", fontSize: "13px", backgroundColor: "var(--bg-input)", color: "var(--text)" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.55" },
  ".cm-content": { padding: "10px 0", caretColor: "var(--accent)" },
  ".cm-gutters": { backgroundColor: "var(--bg-panel)", color: "var(--text-faint)", borderRight: "1px solid var(--border-subtle)" },
  ".cm-lineNumbers .cm-gutterElement": { minWidth: "44px", padding: "0 10px 0 6px" },
  ".cm-activeLine": { backgroundColor: "color-mix(in srgb, var(--accent) 7%, transparent)" },
  ".cm-activeLineGutter": { backgroundColor: "color-mix(in srgb, var(--accent) 12%, transparent)", color: "var(--text)" },
  ".cm-cursor": { borderLeftColor: "var(--accent)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": { backgroundColor: "color-mix(in srgb, var(--accent) 30%, transparent)" },
  ".cm-ps-match": { backgroundColor: "color-mix(in srgb, var(--warning) 28%, transparent)", borderRadius: "2px" },
  ".cm-ps-match-current": { backgroundColor: "color-mix(in srgb, var(--warning) 60%, transparent)", outline: "1px solid var(--warning)" },
  ".cm-ps-status": { marginLeft: "10px", padding: "0 6px", fontSize: "10.5px", fontWeight: "700", color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: "var(--radius)" },
}, { dark: true });

/** Theme plus token colours shared by every code viewer. */
export const codeEditorLook: Extension = [theme, syntaxHighlighting(highlight)];

/** Highlighting for one language. */
export function codeLanguageExtension(id: CodeLanguageId): Extension {
  switch (id) {
    case "plain": return [];
    case "powershell": return StreamLanguage.define(powershellMode);
    case "json": return StreamLanguage.define(json);
    case "javascript": return StreamLanguage.define(javascript);
    case "typescript": return StreamLanguage.define(typescript);
    case "python": return StreamLanguage.define(python);
    case "xml": return StreamLanguage.define(xml);
    case "html": return StreamLanguage.define(html);
    case "shell": return StreamLanguage.define(shell);
    case "sql": return StreamLanguage.define(standardSQL);
    case "css": return StreamLanguage.define(css);
    case "yaml": return StreamLanguage.define(yaml);
    case "vbscript": return StreamLanguage.define(vbScript);
    case "csharp": return StreamLanguage.define(csharp);
    case "php": return php();
  }
}
