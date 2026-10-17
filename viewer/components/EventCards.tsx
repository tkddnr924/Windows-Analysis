"use client";
// Shared pieces of the event card views (service, firewall, BITS, WER,
// Defender, SMB, remote access, RDP cache, scheduled tasks).
import { useEffect, useState, type ElementType, type ReactNode } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CallMadeIcon from "@mui/icons-material/CallMade";
import CallReceivedIcon from "@mui/icons-material/CallReceived";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import PaginationControls from "@/components/PaginationControls";
import type { CsvData } from "@/lib/types";
import { formatEvidenceTimestamp } from "@/lib/timeRange";
import { DIRECTION_COLOR, pageWindow, rowidOf } from "@/lib/eventCards";

const mix = (color: string, percent: number, base = "transparent") => `color-mix(in srgb, ${color} ${percent}%, ${base})`;

/** Evidence timestamp text; untimed rows read "시각 미상". */
export const evidenceTime = (value: string | undefined) => (value ? formatEvidenceTimestamp(value) : "시각 미상");

export interface Bookmarks {
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
}

export const isBookmarked = (row: object, bookmarks: Bookmarks) => bookmarks.bookmarkedRowids?.has(rowidOf(row)) ?? false;

export function BookmarkButton({ row, bookmarks, size = 16 }: { row: object; bookmarks: Bookmarks; size?: number }) {
  const rowid = rowidOf(row);
  const toggle = bookmarks.onToggleBookmark;
  if (!toggle || !Number.isSafeInteger(rowid)) return null;
  const bookmarked = bookmarks.bookmarkedRowids?.has(rowid) ?? false;
  const label = bookmarked ? "북마크 해제" : "북마크 추가";
  return (
    <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(event) => { event.stopPropagation(); toggle(rowid); }} aria-label={label} title={label}
      style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, flexShrink: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>
      {bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: size }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: size }} />}
    </button>
  );
}

export function Pill({ color = "var(--text-dim)", title, children }: { color?: string; title?: string; children: ReactNode }) {
  return <span title={title} style={{ flexShrink: 0, color, fontWeight: 700, fontSize: 11.5, padding: "1px 7px", borderRadius: "var(--radius)", background: mix(color, 15), whiteSpace: "nowrap" }}>{children}</span>;
}

export function PillRow({ children }: { children: ReactNode }) {
  return <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0, flexWrap: "wrap", justifyContent: "flex-end" }}>{children}</span>;
}

export function IconTile({ icon: Icon, tone, title }: { icon: ElementType; tone: string; title?: string }) {
  return (
    <span aria-hidden="true" title={title} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: mix(tone, 15) }}>
      <Icon sx={{ fontSize: 17, color: tone }} />
    </span>
  );
}

/** Inbound/outbound arrow; any other stored direction uses `fallback`. */
export function DirectionMark({ direction, fallback, title }: { direction: string; fallback: ElementType; title?: string }) {
  const icon = direction === "inbound" ? CallReceivedIcon : direction === "outbound" ? CallMadeIcon : fallback;
  return <IconTile icon={icon} tone={DIRECTION_COLOR[direction] ?? "var(--text-faint)"} title={title} />;
}

export function Sep() {
  return <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>;
}

/** Card name: bold, single line. */
export function CardName({ title, children }: { title?: string; children: ReactNode }) {
  return <span title={title} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700 }}>{children}</span>;
}

/** Title line and optional detail line of a card header. */
export function CardMain({ title, sub, wrap = false }: { title: ReactNode; sub?: ReactNode; wrap?: boolean }) {
  return (
    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
      <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0, flexWrap: wrap ? "wrap" : undefined }}>{title}</span>
      {sub && <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>{sub}</span>}
    </span>
  );
}

/** "기록 3" or "기록 2 / 3" (matching / whole card). */
export function CountText({ unit, matched, total }: { unit: string; matched: number; total: number }) {
  return <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>{unit} {matched === total ? total.toLocaleString() : `${matched.toLocaleString()} / ${total.toLocaleString()}`}</span>;
}

/** Card time range; the end drops its date when on the same day. */
export function TimeSpan({ from, to, format = (value) => value }: { from: string; to: string; format?: (value: string) => string }) {
  const end = to && to !== from ? (from && to.slice(0, 10) === from.slice(0, 10) ? format(to).slice(11) : format(to)) : "";
  return (
    <span style={{ flexShrink: 0, color: from ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
      {format(from)}{end && <><span style={{ color: "var(--text-faint)" }}> → </span>{end}</>}
    </span>
  );
}

/** Time column of an event row. */
export function TimeCell({ value, text = value }: { value: string | undefined; text?: string }) {
  return <span style={{ color: value ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{text}</span>;
}

/** Collapsible card: header button (expand, or open the single record) and the expanded region. */
export function CardShell({ label, listItem = false, tone, mark, expandable, open, onActivate, buttonLabel, bookmarked = false, alert = false, side, compact = false, regionLabel, body, children }: {
  label: string;
  listItem?: boolean;
  tone: string;
  mark: ReactNode;
  expandable: boolean;
  open: boolean;
  onActivate: () => void;
  buttonLabel?: string;
  bookmarked?: boolean;
  /** Key finding: tone-colored frame and tint even when closed. */
  alert?: boolean;
  /** Control beside the header button (single-record bookmark). */
  side?: ReactNode;
  compact?: boolean;
  regionLabel: string;
  body?: ReactNode;
  children: ReactNode;
}) {
  const openBackground = mix(tone, 6);
  const restBackground = alert ? mix(tone, 8) : "transparent";
  return (
    <section role={listItem ? "listitem" : undefined} aria-label={label} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ marginBottom: 10, border: `1px solid ${open || alert ? mix(tone, alert ? 70 : 42, "var(--border)") : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", background: open ? openBackground : restBackground }}
        onMouseEnter={(event) => { if (!open && !bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(event) => { event.currentTarget.style.background = open ? openBackground : restBackground; }}>
        <button type="button" onClick={onActivate} aria-expanded={expandable ? open : undefined} aria-label={buttonLabel}
          style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, minHeight: compact ? 46 : 60, padding: compact ? "6px 14px" : "11px 14px", border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
          {mark}
          {children}
          {expandable && <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />}
        </button>
        {side && <span style={{ paddingRight: 10 }}>{side}</span>}
      </div>
      {open && <div role="region" aria-label={regionLabel} style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>{body}</div>}
    </section>
  );
}

/** One stored record inside an expanded card; dimmed when outside the conditions. */
export function EventRow({ row, index, matched, bookmarks, onOpen, openLabel, title, children }: {
  row: object;
  index: number;
  matched: boolean;
  bookmarks: Bookmarks;
  onOpen: () => void;
  openLabel: string;
  title?: string;
  children: ReactNode;
}) {
  const bookmarked = isBookmarked(row, bookmarks);
  return (
    <div className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={onOpen}
      onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
      onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "transparent"; }}
      style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", fontSize: 13, cursor: "pointer", opacity: matched ? 1 : 0.55 }}>
      <button type="button" onClick={(event) => { event.stopPropagation(); onOpen(); }} aria-label={openLabel} title={title}
        style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: "inherit" }}>
        {children}
      </button>
      <BookmarkButton row={row} bookmarks={bookmarks} />
    </div>
  );
}

/** Empty list: no stored rows vs no rows under the conditions. */
export function NoMatch({ total }: { total: number }) {
  return <div role="status" style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>{total === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>;
}

/** Ten records per page inside an expanded card. */
export function PagedEvents<R>({ events, page, onPage, label, render }: { events: R[]; page: number; onPage: (page: number) => void; label: string; render: (row: R, index: number) => ReactNode }) {
  const pager = pageWindow(events.length, page);
  return (
    <>
      {events.slice(pager.start, pager.end).map(render)}
      {pager.pageCount > 1 && (
        <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "4px 0 6px" }}>
          <PaginationControls ariaLabel={label} page={pager.page} pageCount={pager.pageCount} onChange={onPage} summary={pager.summary} />
        </div>
      )}
    </>
  );
}

/** List page, expanded cards and per-card record pages. The list page
 *  returns to the first page whenever a `resetOn` value changes. */
export function useCardState(resetOn: readonly unknown[]) {
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  // Fixed-length dependency list supplied by the caller.
  useEffect(() => setPage(0), resetOn);
  return {
    page,
    setPage,
    isOpen: (key: string) => expanded.has(key),
    toggle: (key: string) => setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    }),
    eventPage: (key: string) => eventPages[key] ?? 0,
    setEventPage: (key: string, next: number) => setEventPages((previous) => ({ ...previous, [key]: next })),
  };
}

export interface CompanionTables {
  tables: Partial<Record<string, CsvData>>;
  /** Tables that could not be read (never shown as empty results). */
  failed: string[];
}

/** Reads companion tables of one _OVERVIEW file, each independently. */
export function useCompanionTables(fullPath: string | undefined, names: readonly string[]): CompanionTables {
  const [state, setState] = useState<CompanionTables>({ tables: {}, failed: [] });
  const key = names.join("\n");
  useEffect(() => {
    setState({ tables: {}, failed: [] });
    if (!fullPath) return;
    let alive = true;
    for (const name of key.split("\n")) {
      window.api.readResultFile(fullPath, name)
        .then((result) => { if (alive) setState((previous) => ({ ...previous, tables: { ...previous.tables, [name]: result } })); })
        .catch(() => { if (alive) setState((previous) => ({ ...previous, failed: [...previous.failed, name] })); });
    }
    return () => { alive = false; };
  }, [fullPath, key]);
  return state;
}

/** Header warning for unreadable companion tables (names on hover). */
export function loadErrorNote(failed: readonly string[], text = "일부 표를 불러오지 못했습니다"): ReactNode {
  if (!failed.length) return undefined;
  return <span role="alert" title={failed.join("\n")} style={{ color: "var(--warning)", fontSize: 11.5 }}>{text}</span>;
}
