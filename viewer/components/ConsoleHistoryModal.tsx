"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Compartment, EditorState, RangeSetBuilder, StateEffect, StateField } from "@codemirror/state";
import { Decoration, EditorView, WidgetType, drawSelection, highlightActiveLine, highlightActiveLineGutter, keymap, lineNumbers, type DecorationSet } from "@codemirror/view";
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from "@codemirror/language";
import { powershellMode } from "@/lib/powershellMode";
import { tags } from "@lezer/highlight";
import CheckIcon from "@mui/icons-material/Check";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowUpOutlinedIcon from "@mui/icons-material/KeyboardArrowUpOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import { useModalDialog } from "@/lib/useModalDialog";
import { buildConsoleDoc, findMatches } from "@/lib/consoleHistoryDoc";
import SelectionDecoder from "./SelectionDecoder";

const STATUS_LABEL: Record<string, string> = { incomplete_continuation: "연결 미완료", missing_line: "줄 누락" };

const highlight = HighlightStyle.define([
  { tag: tags.keyword, color: "var(--accent)", fontWeight: "600" },
  { tag: tags.standard(tags.variableName), color: "#eacb75" },
  { tag: tags.attributeName, color: "#8fcaff" },
  { tag: tags.special(tags.variableName), color: "#b7b0ff" },
  { tag: tags.typeName, color: "#7fd1c7" },
  { tag: tags.string, color: "var(--success)" },
  { tag: tags.number, color: "#f0a36b" },
  { tag: tags.comment, color: "var(--text-faint)", fontStyle: "italic" },
  { tag: tags.operator, color: "var(--text-dim)" },
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

// Search hits: all matches plus the current one, replaced as a set.
const setMatches = StateEffect.define<{ matches: { from: number; to: number }[]; current: number }>();
const matchField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(value, transaction) {
    for (const effect of transaction.effects) {
      if (!effect.is(setMatches)) continue;
      const builder = new RangeSetBuilder<Decoration>();
      effect.value.matches.forEach((match, index) => builder.add(match.from, match.to, Decoration.mark({ class: index === effect.value.current ? "cm-ps-match cm-ps-match-current" : "cm-ps-match" })));
      return builder.finish();
    }
    return value;
  },
  provide: (field) => EditorView.decorations.from(field),
});

class StatusWidget extends WidgetType {
  constructor(private readonly label: string, private readonly raw: string) { super(); }
  eq(other: StatusWidget) { return other.label === this.label; }
  toDOM() {
    const badge = document.createElement("span");
    badge.className = "cm-ps-status";
    badge.textContent = this.label;
    badge.title = this.raw;
    return badge;
  }
}

/** One account's PSReadLine history (ConsoleHost_history.txt) in a read-only
 * code editor: original line numbers, PowerShell colouring, search. */
export default function ConsoleHistoryModal({ account, rows, onClose }: { account: string; rows: Record<string, string>[]; onClose: () => void }) {
  const [wrap, setWrap] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [query, setQuery] = useState("");
  const [current, setCurrent] = useState(0);
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);
  const hostRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const wrapCompartment = useRef(new Compartment());
  // Read at editor creation so a rebuilt editor keeps the current wrap setting.
  const wrapRef = useRef(wrap);
  wrapRef.current = wrap;
  const copyTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(copyTimer.current), []);

  const doc = useMemo(() => buildConsoleDoc(rows), [rows]);
  const matches = useMemo(() => findMatches(doc.text, query), [doc.text, query]);

  useEffect(() => {
    if (!hostRef.current) return;
    // Status badges sit at the end of the restored command's last line.
    const statusField = StateField.define<DecorationSet>({
      create(state) {
        const builder = new RangeSetBuilder<Decoration>();
        let line = 1;
        for (const row of rows) {
          const lastLine = line + (row.command ?? "").split("\n").length - 1;
          const status = row.console_history_status;
          if (status) builder.add(state.doc.line(lastLine).to, state.doc.line(lastLine).to, Decoration.widget({ widget: new StatusWidget(STATUS_LABEL[status] ?? status, status), side: 1 }));
          line = lastLine + 1;
        }
        return builder.finish();
      },
      update: (value) => value,
      provide: (field) => EditorView.decorations.from(field),
    });
    const view = new EditorView({
      parent: hostRef.current,
      state: EditorState.create({
        doc: doc.text,
        extensions: [
          // Evidence text: navigable and selectable, never editable.
          EditorState.readOnly.of(true),
          lineNumbers({ formatNumber: (lineNo) => String(doc.sourceLines[lineNo - 1] ?? "") }),
          highlightActiveLine(),
          highlightActiveLineGutter(),
          drawSelection(),
          StreamLanguage.define(powershellMode),
          syntaxHighlighting(highlight),
          theme,
          matchField,
          statusField,
          wrapCompartment.current.of(wrapRef.current ? EditorView.lineWrapping : []),
          keymap.of([{ key: "Mod-f", run: () => { searchRef.current?.focus(); searchRef.current?.select(); return true; } }]),
        ],
      }),
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, [doc, rows]);

  useEffect(() => {
    viewRef.current?.dispatch({ effects: wrapCompartment.current.reconfigure(wrap ? EditorView.lineWrapping : []) });
  }, [wrap]);

  // Repaint hits and bring the current one into view.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const index = matches.length ? Math.min(current, matches.length - 1) : -1;
    const target = index >= 0 ? matches[index] : null;
    view.dispatch({
      effects: [setMatches.of({ matches, current: index }), ...(target ? [EditorView.scrollIntoView(target.from, { y: "center" })] : [])],
      ...(target ? { selection: { anchor: target.from, head: target.to } } : {}),
    });
  }, [matches, current]);

  function step(delta: number) {
    if (matches.length) setCurrent((value) => (Math.min(value, matches.length - 1) + delta + matches.length) % matches.length);
  }

  async function copyAll() {
    window.clearTimeout(copyTimer.current);
    try {
      await navigator.clipboard.writeText(doc.text);
      setCopied(true);
      setCopyError(false);
      copyTimer.current = window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopyError(true);
      copyTimer.current = window.setTimeout(() => setCopyError(false), 2400);
    }
  }

  const buttonStyle: React.CSSProperties = { display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 4, minHeight: 28, fontSize: 11.5, padding: "3px 10px", background: "var(--bg-elevated)", color: "var(--text-dim)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer" };
  const iconButton: React.CSSProperties = { ...buttonStyle, width: 28, padding: 0 };
  const shown = matches.length ? Math.min(current, matches.length - 1) + 1 : 0;

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 24 }}>
      <div ref={dialogRef} onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} style={{ width: "min(1100px, 94vw)", height: "min(860px, 88vh)", display: "flex", flexDirection: "column", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-elevated)", flexShrink: 0 }}>
          <strong id={titleId} style={{ fontSize: 13 }}>콘솔 히스토리</strong>
          <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{account}</span>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{rows.length.toLocaleString()}개 명령 · ConsoleHost_history · 읽기 전용</span>
          <button type="button" className="nm-btn" onClick={() => setWrap((value) => !value)} style={{ ...buttonStyle, marginLeft: "auto" }}>{wrap ? "줄바꿈 끄기" : "줄바꿈 켜기"}</button>
          <button type="button" className="nm-btn" onClick={copyAll} title={copyError ? "복사 실패" : copied ? "복사됨" : "전체 복사"} aria-label={copyError ? "복사 실패" : copied ? "복사됨" : "콘솔 히스토리 전체 복사"} style={{ ...iconButton, width: 32, color: copyError ? "var(--danger)" : buttonStyle.color }}>
            {copied ? <CheckIcon sx={{ fontSize: 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
          </button>
          <button type="button" className="nm-btn" onClick={onClose} data-dialog-autofocus aria-label="콘솔 히스토리 닫기" title="닫기 (Esc)" style={{ ...buttonStyle, fontSize: 16, lineHeight: 1, padding: "2px 8px" }}>×</button>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "7px 14px", borderBottom: "1px solid var(--border-subtle)", background: "var(--bg-panel)", flexShrink: 0 }}>
          <SearchOutlinedIcon sx={{ fontSize: 16, color: "var(--text-faint)" }} />
          <input
            ref={searchRef}
            value={query}
            onChange={(event) => { setQuery(event.target.value); setCurrent(0); }}
            onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); step(event.shiftKey ? -1 : 1); } }}
            placeholder="히스토리 검색 (Enter 다음 · Shift+Enter 이전 · ⌘F)"
            aria-label="콘솔 히스토리 검색"
            style={{ flex: 1, maxWidth: 420, height: 28, padding: "0 9px", fontSize: 12.5, color: "var(--text)", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", outline: "none" }}
          />
          <span role="status" style={{ minWidth: 64, fontSize: 11.5, color: query && !matches.length ? "var(--warning)" : "var(--text-faint)", fontFamily: "var(--mono)" }}>{query ? (matches.length ? `${shown.toLocaleString()} / ${matches.length.toLocaleString()}` : "결과 없음") : ""}</span>
          <button type="button" className="nm-btn" onClick={() => step(-1)} disabled={!matches.length} aria-label="이전 검색 결과" title="이전 (Shift+Enter)" style={{ ...iconButton, opacity: matches.length ? 1 : 0.45 }}><KeyboardArrowUpOutlinedIcon sx={{ fontSize: 17 }} /></button>
          <button type="button" className="nm-btn" onClick={() => step(1)} disabled={!matches.length} aria-label="다음 검색 결과" title="다음 (Enter)" style={{ ...iconButton, opacity: matches.length ? 1 : 0.45 }}><KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17 }} /></button>
        </div>
        {copyError && <div role="status" style={{ padding: "6px 14px", color: "var(--danger)", borderBottom: "1px solid var(--border-subtle)", fontSize: 11.5 }}>클립보드에 복사하지 못했습니다. 권한을 확인한 뒤 다시 시도하세요.</div>}
        <div ref={hostRef} style={{ flex: 1, minHeight: 0 }} />
        <SelectionDecoder containerRef={hostRef} />
      </div>
    </div>
  );
}
