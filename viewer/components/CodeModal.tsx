"use client";

import { useEffect, useId, useRef, useState } from "react";
import { Compartment, EditorState } from "@codemirror/state";
import { EditorView, drawSelection, highlightActiveLine, highlightActiveLineGutter, lineNumbers } from "@codemirror/view";
import CheckIcon from "@mui/icons-material/Check";
import CodeOutlinedIcon from "@mui/icons-material/CodeOutlined";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import { useModalDialog } from "@/lib/useModalDialog";
import { CODE_LANGUAGES, detectCodeLanguage, type CodeLanguageId } from "@/lib/codeLanguage";
import { SelectDropdown } from "./FilterControls";
import SelectionDecoder from "./SelectionDecoder";
import { codeEditorLook, codeLanguageExtension } from "./codeEditor";

// Full-screen read-only code viewer for any long code field: line numbers,
// highlighting by a chosen language, wrap toggle, copy, Escape/outside close.
export default function CodeModal({
  code,
  copyValue = code,
  title = "코드 보기",
  onClose,
}: {
  code: string;
  /** Clipboard value when `code` is a formatted view of stored text. */
  copyValue?: string;
  title?: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [wrap, setWrap] = useState(true);
  const [language, setLanguage] = useState<CodeLanguageId>(() => detectCodeLanguage(code));
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);
  const hostRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const wrapCompartment = useRef(new Compartment());
  const languageCompartment = useRef(new Compartment());
  // Read at creation so a rebuilt editor keeps the current choices.
  const settings = useRef({ wrap, language });
  settings.current = { wrap, language };

  useEffect(() => {
    if (!hostRef.current) return;
    const view = new EditorView({
      parent: hostRef.current,
      state: EditorState.create({
        doc: code,
        extensions: [
          // Evidence text: selectable, never editable.
          EditorState.readOnly.of(true),
          lineNumbers(),
          highlightActiveLine(),
          highlightActiveLineGutter(),
          drawSelection(),
          codeEditorLook,
          languageCompartment.current.of(codeLanguageExtension(settings.current.language)),
          wrapCompartment.current.of(settings.current.wrap ? EditorView.lineWrapping : []),
        ],
      }),
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, [code]);

  useEffect(() => {
    viewRef.current?.dispatch({ effects: wrapCompartment.current.reconfigure(wrap ? EditorView.lineWrapping : []) });
  }, [wrap]);

  useEffect(() => {
    viewRef.current?.dispatch({ effects: languageCompartment.current.reconfigure(codeLanguageExtension(language)) });
  }, [language]);

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(copyValue);
      setCopied(true);
      setCopyError(false);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopyError(true);
      window.setTimeout(() => setCopyError(false), 2400);
    }
  }

  const btnStyle: React.CSSProperties = { display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 4, minHeight: 28, fontSize: 11.5, padding: "3px 10px", background: "var(--bg-elevated)", color: "var(--text-dim)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer" };

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 24 }}>
      <div ref={dialogRef} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} style={{ width: "min(1100px, 94vw)", height: "min(860px, 88vh)", display: "flex", flexDirection: "column", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-elevated)", flexShrink: 0 }}>
          <strong id={titleId} style={{ fontSize: 13 }}>{title}</strong>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{code.length.toLocaleString()}자 · 읽기 전용</span>
          <span style={{ marginLeft: "auto" }}>
            <SelectDropdown icon={<CodeOutlinedIcon sx={{ fontSize: 15 }} />} label="형식" ariaLabel="강조 형식" options={CODE_LANGUAGES.map(({ id, label }) => ({ value: id, label }))} value={language} defaultValue={language} onChange={setLanguage} align="right" />
          </span>
          <button className="nm-btn" onClick={() => setWrap((w) => !w)} style={btnStyle}>
            {wrap ? "줄바꿈 끄기" : "줄바꿈 켜기"}
          </button>
          <button className="nm-btn" onClick={copyCode} title={copyError ? "복사 실패" : copied ? "복사됨" : "복사"} aria-label={copyError ? "복사 실패" : copied ? "복사됨" : "코드 복사"} style={{ ...btnStyle, width: 32, padding: 0, color: copyError ? "var(--danger)" : btnStyle.color }}>
            {copied ? <CheckIcon sx={{ fontSize: 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
          </button>
          <button className="nm-btn" onClick={onClose} data-dialog-autofocus aria-label="코드 보기 닫기" title="닫기 (Esc)" style={{ ...btnStyle, fontSize: 16, lineHeight: 1, padding: "2px 8px" }}>×</button>
        </div>
        {copyError && <div role="status" style={{ padding: "6px 14px", color: "var(--danger)", borderBottom: "1px solid var(--border-subtle)", fontSize: 11.5 }}>클립보드에 복사하지 못했습니다. 권한을 확인한 뒤 다시 시도하세요.</div>}
        <div ref={hostRef} style={{ flex: 1, minHeight: 0 }} />
        <SelectionDecoder containerRef={hostRef} />
      </div>
    </div>
  );
}
