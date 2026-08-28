"use client";

// 공용 페이지네이션 — 모든 뷰가 같은 UI를 쓴다:
// [처음][이전] 1 2 … n-1 n [다음][끝] (+ 선택적 요약 텍스트).
// page는 0부터 시작하고, 표시 번호는 1부터다.
import type { CSSProperties } from "react";
import FirstPageIcon from "@mui/icons-material/FirstPage";
import LastPageIcon from "@mui/icons-material/LastPage";
import NavigateBeforeOutlinedIcon from "@mui/icons-material/NavigateBeforeOutlined";
import NavigateNextOutlinedIcon from "@mui/icons-material/NavigateNextOutlined";

function controlStyle(disabled: boolean, active = false): CSSProperties {
  return {
    display: "inline-grid",
    placeItems: "center",
    minWidth: 27,
    height: 27,
    padding: "0 7px",
    border: `1px solid ${active ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border)"}`,
    borderRadius: "var(--radius-sm)",
    background: active ? "var(--accent-subtle)" : "var(--bg-elevated)",
    color: active ? "var(--accent)" : "var(--text-dim)",
    fontSize: 11,
    fontWeight: active ? 700 : 500,
    fontVariantNumeric: "tabular-nums",
    cursor: disabled || active ? "default" : "pointer",
    opacity: disabled ? 0.45 : 1,
  };
}

// 번호 창: 처음 두 쪽, 현재 ±1, 마지막 두 쪽만 표시하고 사이는 …로 줄인다.
function pageWindow(page: number, pageCount: number): (number | "gap")[] {
  if (pageCount <= 9) return Array.from({ length: pageCount }, (_, index) => index);
  const wanted = [0, 1, page - 1, page, page + 1, pageCount - 2, pageCount - 1]
    .filter((candidate) => candidate >= 0 && candidate < pageCount);
  const pages = [...new Set(wanted)].sort((a, b) => a - b);
  const out: (number | "gap")[] = [];
  let previous = -1;
  for (const candidate of pages) {
    if (previous >= 0 && candidate - previous > 1) out.push("gap");
    out.push(candidate);
    previous = candidate;
  }
  return out;
}

export default function PaginationControls({
  page,
  pageCount,
  onChange,
  summary,
  disabled = false,
  ariaLabel = "페이지",
}: {
  /** 현재 쪽 (0부터). */
  page: number;
  pageCount: number;
  onChange: (page: number) => void;
  /** 컨트롤 옆에 붙는 요약 텍스트 (예: "(1–10 / 138,809)"). */
  summary?: string;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  if (pageCount <= 1) return null;
  const safePage = Math.min(Math.max(page, 0), pageCount - 1);
  const go = (target: number) => {
    if (disabled) return;
    const next = Math.min(Math.max(target, 0), pageCount - 1);
    if (next !== safePage) onChange(next);
  };
  const atFirst = disabled || safePage === 0;
  const atLast = disabled || safePage >= pageCount - 1;
  return (
    <nav aria-label={ariaLabel} style={{ display: "flex", alignItems: "center", justifyContent: "center", flexWrap: "wrap", gap: 5, whiteSpace: "nowrap" }}>
      <button className="nm-btn" type="button" aria-label="첫 페이지" title="첫 페이지" disabled={atFirst} onClick={() => go(0)} style={controlStyle(atFirst)}>
        <FirstPageIcon sx={{ fontSize: 16 }} />
      </button>
      <button className="nm-btn" type="button" aria-label="이전 페이지" title="이전 페이지" disabled={atFirst} onClick={() => go(safePage - 1)} style={controlStyle(atFirst)}>
        <NavigateBeforeOutlinedIcon sx={{ fontSize: 16 }} />
      </button>
      {pageWindow(safePage, pageCount).map((item, index) =>
        item === "gap" ? (
          <span key={`gap-${index}`} aria-hidden="true" style={{ minWidth: 18, textAlign: "center", color: "var(--text-faint)", fontSize: 11 }}>…</span>
        ) : (
          <button
            key={item}
            className="nm-btn"
            type="button"
            aria-label={`${item + 1} 페이지`}
            aria-current={item === safePage ? "page" : undefined}
            disabled={disabled || item === safePage}
            onClick={() => go(item)}
            style={controlStyle(disabled, item === safePage)}
          >
            {(item + 1).toLocaleString()}
          </button>
        ),
      )}
      <button className="nm-btn" type="button" aria-label="다음 페이지" title="다음 페이지" disabled={atLast} onClick={() => go(safePage + 1)} style={controlStyle(atLast)}>
        <NavigateNextOutlinedIcon sx={{ fontSize: 16 }} />
      </button>
      <button className="nm-btn" type="button" aria-label="마지막 페이지" title="마지막 페이지" disabled={atLast} onClick={() => go(pageCount - 1)} style={controlStyle(atLast)}>
        <LastPageIcon sx={{ fontSize: 16 }} />
      </button>
      {summary && <span style={{ marginLeft: 5, color: "var(--text-faint)", fontSize: 11.5, fontVariantNumeric: "tabular-nums" }}>{summary}</span>}
    </nav>
  );
}
