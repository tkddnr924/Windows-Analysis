"use client";

import { useContext, useEffect, useState } from "react";
import CheckIcon from "@mui/icons-material/Check";
import ChevronRightOutlinedIcon from "@mui/icons-material/ChevronRightOutlined";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import LinkOutlinedIcon from "@mui/icons-material/LinkOutlined";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import { resolveArtifactView, type FieldSpec } from "@/lib/artifactViews";
import { RecordScopeContext } from "@/lib/recordScope";
import type { DBRow, FetchLinkedRows } from "@/lib/types";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { useModalDialog } from "@/lib/useModalDialog";
import ArtifactDetailView from "./ArtifactDetailView";

interface RowDetailPanelProps {
  row: Record<string, string>;
  columns: string[];
  focusedColumn: string | null;
  /** Selected evidence time; never merged into the source row. */
  evidenceTime?: { value: string; label?: string };
  fileBaseName: string;
  onClose: () => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** Host evidence directory for Browser Cache body recovery. */
  hostDir?: string;
  /** Exact SID display mapping for this record's authoritative host. */
  accountDirectory?: AccountDirectory;
  /** Bookmark state + toggle for this row, bound by the parent. Omitted when
   * the host view has no bookmarking (then no bookmark control is shown). */
  isBookmarked?: boolean;
  onToggleBookmark?: () => void;
  /** Render inside a persistent view column instead of as an overlay drawer. */
  variant?: "drawer" | "docked";
  /** Optional stable field-level bookmark contract. Used by MFT SI/FN times. */
  onToggleFieldBookmark?: (field: string) => void;
  isFieldBookmarked?: (field: string) => boolean;
  /** Cross-artifact evidence links shown by the same shared detail surface. */
  relatedEvidence?: { id: string; label: string; subtitle?: string; onOpen: () => void }[];
}

function tryPrettyJson(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

// Turn literal escape sequences ("\r\n", "\n", "\t") — which many EventData
// blobs store as two-character text, not real whitespace — into actual line
// breaks/tabs so multi-line content reads normally. Display-only.
function unescapeWhitespace(s: string): string {
  return s
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\n")
    .replace(/\\t/g, "\t");
}

function RawFieldValue({ column, value, focused }: { column: string; value: string; focused: boolean }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [beautified, setBeautified] = useState(true);
  const [unescaped, setUnescaped] = useState(false);
  const pretty = tryPrettyJson(value);
  const isJson = pretty !== null;
  const hasEscapes = /\\[rnt]/.test(value);
  const baseText = isJson && beautified ? pretty! : value;
  const shownText = unescaped ? unescapeWhitespace(baseText) : baseText;
  const isEmpty = !value;

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setCopyError(false);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopyError(true);
      setTimeout(() => setCopyError(false), 2400);
    }
  }

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(118px, 32%) minmax(0, 1fr) auto",
        alignItems: "start",
        columnGap: 12,
        padding: "10px 16px",
        borderBottom: "1px solid var(--border-subtle)",
        background: focused ? "var(--accent-subtle)" : "transparent",
        borderLeft: `2px solid ${focused ? "var(--accent)" : "transparent"}`,
      }}
    >
      <div style={{ paddingTop: 2, minWidth: 0 }}>
        <div style={{ color: focused ? "var(--accent)" : "var(--text-dim)", fontWeight: 650, fontFamily: "var(--mono)", fontSize: 11.5, overflowWrap: "anywhere" }}>{column}</div>
      </div>
      <div style={{ minWidth: 0 }}>
        {isEmpty ? (
          <span style={{ fontSize: 12, color: "var(--text-faint)" }}>값 없음</span>
        ) : (
          <pre
            style={{
              margin: 0,
              fontFamily: "var(--mono)",
              fontSize: 12,
              lineHeight: 1.48,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              color: "var(--text)",
            }}
          >
            {shownText}
          </pre>
        )}
      </div>
      {!isEmpty && (
        <div style={{ display: "inline-flex", alignItems: "center", gap: 4, paddingTop: 0 }}>
          {isJson && (
          <button
            className="nm-btn"
            onClick={() => setBeautified((b) => !b)}
            title={beautified ? "원본(압축) 보기" : "보기 좋게 정렬"}
            style={{
              fontSize: 11,
              padding: "2px 8px",
              background: "var(--bg-elevated)",
              color: "var(--accent)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius)",
              cursor: "pointer",
            }}
          >
            {"{ }"}
          </button>
        )}
        {hasEscapes && (
          <button
            className="nm-btn"
            onClick={() => setUnescaped((u) => !u)}
            title={unescaped ? "이스케이프 원본(\\r \\n \\t) 보기" : "\\r \\n \\t 를 실제 줄바꿈·탭으로 치환"}
            style={{
              fontSize: 11,
              padding: "2px 8px",
              background: unescaped ? "var(--accent-subtle)" : "var(--bg-elevated)",
              color: "var(--accent)",
              border: `1px solid ${unescaped ? "var(--accent)" : "var(--border)"}`,
              borderRadius: "var(--radius)",
              cursor: "pointer",
            }}
          >
            ↵ \n 치환
          </button>
        )}
        <button
          className="nm-btn"
          onClick={copy}
          title={copyError ? "복사 실패" : copied ? "복사됨" : "값 복사"}
          aria-label={copyError ? `${column} 복사 실패` : copied ? `${column} 복사됨` : `${column} 값 복사`}
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: 32,
            height: 28,
            padding: 0,
            background: "var(--bg-elevated)",
            color: "var(--text-dim)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
            cursor: "pointer",
          }}
        >
          {copied ? <CheckIcon sx={{ fontSize: 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15, color: copyError ? "var(--danger)" : undefined }} />}
        </button>
        {copyError && <span role="status" style={{ color: "var(--danger)", fontSize: 10.5, whiteSpace: "nowrap" }}>복사 실패</span>}
        </div>
      )}
    </div>
  );
}

export default function RowDetailPanel({ row, columns, focusedColumn, evidenceTime, fileBaseName, onClose, onNavigate, onFetchLinkedRows, hostDir, accountDirectory, isBookmarked, onToggleBookmark, variant = "drawer", onToggleFieldBookmark, isFieldBookmarked, relatedEvidence = [] }: RowDetailPanelProps) {
  const scope = useContext(RecordScopeContext);
  const rowid = Number((row as Record<string, unknown>).__rowid);
  // 좌표는 원시 값으로만 의존한다 — 범위 객체는 렌더마다 새로 만들어질 수 있어
  // 객체 동일성에 의존하면 조회가 끝없이 되풀이된다.
  const scopePath = scope?.fullPath ?? "";
  const scopeTable = scope?.tableName ?? "";
  const canReadChildren = Boolean(scopePath && scopeTable && Number.isSafeInteger(rowid));

  const spec = resolveArtifactView(fileBaseName, columns);
  const [showRaw, setShowRaw] = useState(!spec);
  const docked = variant === "docked";
  const dialogRef = useModalDialog(onClose, !docked);

  // Detail-only child tables (ExecutionTimes, TaskActions, …) stay out of the
  // listings and are read per row when it is opened.
  const childTables = spec?.childTables;
  const [children, setChildren] = useState<Record<string, DBRow[]>>({});
  useEffect(() => {
    setChildren({});
    if (!canReadChildren || !childTables?.length) return;
    let alive = true;
    Promise.all(childTables.map(async (child) => {
      const childRows = await window.api.readRecordChildren(scopePath, scopeTable, rowid, child.table).catch(() => [] as DBRow[]);
      return [child.table, childRows] as const;
    })).then((entries) => {
      if (alive) setChildren(Object.fromEntries(entries));
    });
    return () => { alive = false; };
  }, [canReadChildren, scopePath, scopeTable, rowid, childTables]);

  // 값이 있는 자식 표만 그린다 — 근거가 없으면 섹션을 만들지 않는다.
  const childSections = (childTables ?? [])
    .map((child) => ({ child, childRows: children[child.table] ?? [] }))
    .filter((entry) => entry.childRows.length > 0)
    .map(({ child, childRows }) => (
      <section key={child.table} style={{ padding: "14px 16px 18px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="dfir-section-label" style={{ marginBottom: 7 }}>{child.heading} ({childRows.length})</div>
        {childRows.map((childRow, index) => (
          <div key={`${child.table}-${index}`} style={{ marginBottom: 6, padding: "8px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
            {child.summary ? (
              <div style={{ fontSize: 12.5, fontFamily: "var(--mono)", color: "var(--text)", wordBreak: "break-all" }}>{child.summary(childRow) || "값 없음"}</div>
            ) : (
              (child.fields ?? Object.keys(childRow).map((key): FieldSpec => ({ key })))
                .filter((field) => childRow[field.key])
                .map((field) => (
                  <div key={field.key} style={{ display: "grid", gridTemplateColumns: "minmax(96px, 30%) minmax(0, 1fr)", gap: 8, padding: "2px 0" }}>
                    <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{field.label ?? field.key}</span>
                    <span style={{ fontSize: 12, color: "var(--text)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{field.valueLabels?.[childRow[field.key]] ?? childRow[field.key]}</span>
                  </div>
                ))
            )}
          </div>
        ))}
      </section>
    ));


  return (
    <div
      onClick={docked ? undefined : onClose}
      style={docked ? {
        height: "100%",
        minHeight: 0,
        display: "flex",
        background: "var(--bg-panel)",
      } : {
        position: "fixed",
        inset: 0,
        background: "rgba(1,4,9,0.6)",
        display: "flex",
        justifyContent: "flex-end",
        zIndex: 100,
        animation: "fadeIn 0.15s ease",
      }}
    >
      <style>{`
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideIn { from { transform: translateX(24px); opacity: 0.6; } to { transform: translateX(0); opacity: 1; } }
      `}</style>
      <div
        ref={dialogRef}
        onClick={(e) => e.stopPropagation()}
        role={docked ? undefined : "dialog"}
        aria-modal={docked ? undefined : true}
        aria-label="증거 상세"
        tabIndex={docked ? undefined : -1}
        style={{
          width: docked ? "100%" : 480,
          maxWidth: docked ? "none" : "80vw",
          height: "100%",
          background: "var(--bg-panel)",
          borderLeft: docked ? "none" : "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          boxShadow: docked ? "none" : "var(--shadow-panel)",
          animation: docked ? undefined : "slideIn 0.18s ease",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            padding: "12px 16px",
            borderBottom: "1px solid var(--border)",
            flexShrink: 0,
            background: "var(--bg-elevated)",
          }}
        >
          <div style={{ minWidth: 0, fontSize: 14, fontWeight: 750, letterSpacing: "-0.01em" }}>증거 상세</div>
          {spec && (
            <div
              role="group"
              aria-label="상세 정보 표시 범위"
              style={{
                marginLeft: 10,
                display: "inline-flex",
                gap: 2,
                padding: 2,
                background: "var(--bg-input)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
              }}
            >
              <button
                className={!showRaw ? "nm-btn" : undefined}
                onClick={() => setShowRaw(false)}
                aria-pressed={!showRaw}
                style={{
                  fontSize: 11.5,
                  minHeight: 26,
                  padding: "3px 11px",
                  background: !showRaw ? "var(--accent-subtle)" : "transparent",
                  color: !showRaw ? "var(--accent)" : "var(--text-faint)",
                  border: "none",
                  borderRadius: "var(--radius)",
                  cursor: "pointer",
                  fontWeight: !showRaw ? 700 : 550,
                  whiteSpace: "nowrap",
                }}
              >
                주요 정보
              </button>
              <button
                className={showRaw ? "nm-btn" : undefined}
                onClick={() => setShowRaw(true)}
                aria-pressed={showRaw}
                style={{
                  fontSize: 11.5,
                  minHeight: 26,
                  padding: "3px 11px",
                  background: showRaw ? "var(--accent-subtle)" : "transparent",
                  color: showRaw ? "var(--accent)" : "var(--text-faint)",
                  border: "none",
                  borderRadius: "var(--radius)",
                  cursor: "pointer",
                  fontWeight: showRaw ? 700 : 550,
                }}
              >
                전체 필드
              </button>
            </div>
          )}
          {onToggleBookmark && (
            <button
              className={isBookmarked ? "dfir-bookmark-control nm-btn" : "nm-btn"}
              onClick={onToggleBookmark}
              title={isBookmarked ? "북마크 해제" : "북마크에 추가"}
              style={{
                marginLeft: "auto",
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                fontSize: 11.5,
                padding: "5px 10px",
                background: isBookmarked ? "var(--bookmark-subtle)" : "var(--bg-elevated)",
                color: isBookmarked ? "var(--bookmark)" : "var(--text-dim)",
                border: `1px solid ${isBookmarked ? "var(--bookmark-border)" : "var(--border)"}`,
                borderRadius: "var(--radius)",
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              {isBookmarked ? "북마크됨" : "북마크"}
            </button>
          )}
          <button
            onClick={onClose}
            data-dialog-autofocus={!docked ? true : undefined}
            aria-label={docked ? "선택 항목 닫기" : "상세 보기 닫기"}
            style={{
              marginLeft: onToggleBookmark ? 8 : "auto",
              background: "transparent",
              border: "none",
              color: "var(--text-dim)",
              fontSize: 20,
              cursor: "pointer",
              lineHeight: 1,
              padding: 4,
              borderRadius: "var(--radius)",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            ×
          </button>
        </div>
        <div data-detail-scroll-container style={{ overflowY: "auto", flex: 1 }}>
          {spec && !showRaw ? (
            <>
              <ArtifactDetailView spec={spec} row={row} evidenceTime={evidenceTime} onNavigate={onNavigate} onFetchLinkedRows={onFetchLinkedRows} hostDir={hostDir} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />
              {relatedEvidence.length > 0 && (
                <section style={{ padding: "14px 16px 18px", borderBottom: "1px solid var(--border-subtle)" }}>
                  <div className="dfir-section-label" style={{ marginBottom: 7 }}>교차 참조 증거</div>
                  {relatedEvidence.map((evidence) => {
                    // "Jumplist · Administrator" → 아티팩트 배지 + 계정으로 분해해 표시.
                    const [kind, ...accountParts] = evidence.label.split(" · ");
                    const account = accountParts.join(" · ");
                    const RefIcon = /jumplist/i.test(kind) ? DescriptionOutlinedIcon : /shellbag/i.test(kind) ? FolderOpenOutlinedIcon : LinkOutlinedIcon;
                    return (
                      <button key={evidence.id} type="button" onClick={evidence.onOpen} style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, minHeight: 50, marginBottom: 6, padding: "8px 10px", textAlign: "left", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text)", cursor: "pointer", transition: "background .15s ease" }}
                        onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
                        onMouseLeave={(event) => { event.currentTarget.style.background = "var(--bg-elevated)"; }}>
                        <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, flexShrink: 0, borderRadius: "var(--radius)", background: "var(--accent-subtle)" }}>
                          <RefIcon sx={{ fontSize: 16, color: "var(--accent)" }} />
                        </span>
                        <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                          <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                            <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius)", padding: "0 7px", whiteSpace: "nowrap" }}>{kind}</span>
                            {account && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 650 }}>{account}</span>}
                          </span>
                          {evidence.subtitle && <span style={{ minWidth: 0, fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{evidence.subtitle}</span>}
                        </span>
                        <ChevronRightOutlinedIcon aria-hidden="true" sx={{ color: "var(--text-faint)", fontSize: 17, flexShrink: 0 }} />
                      </button>
                    );
                  })}
                </section>
              )}
              {childSections}
            </>
          ) : (
            <>
              {columns.map((col) => (
                <RawFieldValue key={col} column={col} value={row[col] ?? ""} focused={col === focusedColumn} />
              ))}
              {childSections}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
