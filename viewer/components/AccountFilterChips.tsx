"use client";

// 계정별 체크 필터 — 모든 뷰가 같은 UI를 쓴다. 계정이 많아도 자리를 차지하지
// 않도록 버튼 하나로 접고, 클릭하면 드롭다운에서 체크로 고른다.
// 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
import { useState } from "react";
import PersonOutlineOutlinedIcon from "@mui/icons-material/PersonOutlineOutlined";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";

export default function AccountFilterChips({
  accounts,
  hidden,
  onToggle,
  onReset,
  accountDirectory,
  ariaLabel = "계정 필터",
  emptyLabel = "계정 없음",
  align = "left",
}: {
  /** 데이터에 존재하는 계정 값 목록(정렬된 원본 값). */
  accounts: string[];
  hidden: Set<string>;
  onToggle: (account: string) => void;
  onReset: () => void;
  accountDirectory?: AccountDirectory;
  ariaLabel?: string;
  emptyLabel?: string;
  /** 드롭다운 정렬 — 화면 오른쪽 끝에 붙는 버튼은 "right". */
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  if (accounts.length === 0) return null;
  const visibleCount = accounts.length - hidden.size;
  const filtering = hidden.size > 0;
  return (
    <div style={{ position: "relative", display: "inline-flex" }}>
      <button
        type="button"
        className="nm-btn"
        aria-expanded={open}
        aria-label={ariaLabel}
        title="계정별 표시 선택"
        onClick={() => setOpen((value) => !value)}
        style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 5, minHeight: 30, padding: "4px 10px", background: filtering ? "var(--accent-subtle)" : "var(--bg-elevated)", color: filtering ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${filtering ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12, fontWeight: filtering ? 650 : 500, whiteSpace: "nowrap" }}
      >
        <PersonOutlineOutlinedIcon sx={{ fontSize: 16 }} />
        계정 {visibleCount}/{accounts.length}
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
          <div role="group" aria-label={ariaLabel} style={{ position: "absolute", top: "calc(100% + 6px)", [align]: 0, zIndex: 41, minWidth: 235, maxHeight: 320, overflowY: "auto", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", padding: 6 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "4px 8px 7px", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text)" }}>계정 표시</span>
              {filtering && (
                <button type="button" onClick={onReset} style={{ background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontSize: 11.5, fontWeight: 600, padding: 0 }}>
                  전체 선택
                </button>
              )}
            </div>
            {accounts.map((account) => {
              const checked = !hidden.has(account);
              const label = account ? resolveAccountDisplay(account, accountDirectory) || account : emptyLabel;
              return (
                <button
                  key={account || "(없음)"}
                  type="button"
                  aria-pressed={checked}
                  onClick={() => onToggle(account)}
                  style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, minHeight: 32, padding: "4px 8px", background: "transparent", border: "none", borderRadius: "var(--radius-sm)", color: checked ? "var(--text)" : "var(--text-faint)", cursor: "pointer", fontSize: 12.5, fontWeight: checked ? 600 : 500, textAlign: "left" }}
                  onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}
                >
                  <span aria-hidden="true" style={{ color: checked ? "var(--accent)" : "var(--text-faint)", fontSize: 13 }}>{checked ? "☑" : "☐"}</span>
                  <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{label}</span>
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
