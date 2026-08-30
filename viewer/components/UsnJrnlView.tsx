"use client";
// USN 저널($UsnJrnl:$J) 뷰 — NTFS 변경 저널의 생성·삭제·이름 변경·데이터 변경
// 이벤트를 원장 형태로 보여준다. 수십만 행 규모라 서버 페이지네이션
// (usnjrnl_page)으로 필터·검색·기간을 SQLite 쪽에서 처리한다.
import { useEffect, useMemo, useRef, useState } from "react";
import AddCircleOutlineOutlinedIcon from "@mui/icons-material/AddCircleOutlineOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import DeleteOutlineOutlinedIcon from "@mui/icons-material/DeleteOutlineOutlined";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import DriveFileRenameOutlineOutlinedIcon from "@mui/icons-material/DriveFileRenameOutlineOutlined";
import EditNoteOutlinedIcon from "@mui/icons-material/EditNoteOutlined";
import FormatListBulletedOutlinedIcon from "@mui/icons-material/FormatListBulletedOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import RowDetailPanel from "./RowDetailPanel";
import type { CsvData } from "@/lib/types";
import { toBound, type TimeRange } from "@/lib/timeRange";

type Row = Record<string, string>;
type ReasonMeta = { label: string; icon: typeof HistoryOutlinedIcon; tone: string };

interface Props {
  dbPath: string;
  timeRange?: TimeRange;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
}

const PAGE = 10;
const REASON_ALL = "전체";
// 상태 필터 — 배지 판정과 같은 우선순위 카테고리(백엔드에서 판정)를 보낸다.
const REASON_FILTERS: { label: string; pattern: string }[] = [
  { label: REASON_ALL, pattern: "" },
  { label: "생성", pattern: "create" },
  { label: "삭제", pattern: "delete" },
  { label: "이름 변경", pattern: "rename" },
  { label: "데이터 변경", pattern: "data" },
  { label: "정보 변경", pattern: "info" },
  { label: "보안 변경", pattern: "security" },
];

function rowId(row: Row): number {
  return Number((row as Record<string, unknown>).__rowid);
}

/// reason 플래그 묶음에서 대표 유형 하나를 뽑아 배지로 쓴다 (우선순위:
/// 삭제 > 생성 > 이름 변경 > 데이터 > 정보/보안 > 첫 플래그).
function reasonMeta(reason: string): ReasonMeta {
  if (reason.includes("FILE_DELETE")) return { label: "삭제", icon: DeleteOutlineOutlinedIcon, tone: "var(--danger)" };
  if (reason.includes("FILE_CREATE")) return { label: "생성", icon: AddCircleOutlineOutlinedIcon, tone: "var(--success)" };
  if (reason.includes("RENAME_OLD_NAME") && reason.includes("RENAME_NEW_NAME"))
    return { label: "이름 변경", icon: DriveFileRenameOutlineOutlinedIcon, tone: "var(--accent)" };
  if (reason.includes("RENAME_OLD_NAME")) return { label: "이름 변경 (이전)", icon: DriveFileRenameOutlineOutlinedIcon, tone: "var(--accent)" };
  if (reason.includes("RENAME_NEW_NAME")) return { label: "이름 변경 (새)", icon: DriveFileRenameOutlineOutlinedIcon, tone: "var(--accent)" };
  if (reason.includes("DATA_")) return { label: "데이터 변경", icon: EditNoteOutlinedIcon, tone: "var(--warning)" };
  if (reason.includes("BASIC_INFO_CHANGE")) return { label: "정보 변경", icon: DescriptionOutlinedIcon, tone: "var(--text-dim)" };
  if (reason.includes("SECURITY_CHANGE")) return { label: "보안 변경", icon: DescriptionOutlinedIcon, tone: "var(--text-dim)" };
  const first = reason.split("|")[0] || "기록";
  return { label: first, icon: HistoryOutlinedIcon, tone: "var(--text-dim)" };
}

export default function UsnJrnlView({ dbPath, timeRange, bookmarkedRowids, onToggleBookmark }: Props) {
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [reasonLabel, setReasonLabel] = useState(REASON_ALL);
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(0);
  const [data, setData] = useState<CsvData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<Row | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const requestSeq = useRef(0);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search), 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  const reasonPattern = REASON_FILTERS.find((entry) => entry.label === reasonLabel)?.pattern ?? "";
  const start = toBound(timeRange?.start ?? "", "start");
  const end = toBound(timeRange?.end ?? "", "end");

  useEffect(() => setPage(0), [debouncedSearch, reasonPattern, order, start, end, dbPath]);
  useEffect(() => {
    const seq = ++requestSeq.current;
    setLoading(true);
    window.api
      .usnJrnlPage(dbPath, { search: debouncedSearch, reason: reasonPattern, start, end, ascending: order === "asc", offset: page * PAGE, limit: PAGE })
      .then((result) => {
        if (requestSeq.current !== seq) return;
        setData(result);
        setError(null);
        setLoading(false);
        scrollRef.current?.scrollTo({ top: 0 });
      })
      .catch((e) => {
        if (requestSeq.current !== seq) return;
        setError(String(e));
        setLoading(false);
      });
  }, [dbPath, debouncedSearch, reasonPattern, start, end, order, page]);

  const rows = useMemo(() => (data?.rows ?? []) as Row[], [data]);
  const total = data?.rowCount ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const rangeOn = Boolean(start || end);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <ViewHeader
        icon={HistoryOutlinedIcon}
        title="USN 저널"
        meta={`${total.toLocaleString()}건`}
        right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? "기간 필터 적용" : "전체 기간"}</span>}
      >
        <HeaderSearchInput value={search} onChange={setSearch} placeholder="파일명 검색" ariaLabel="USN 저널 검색" width={300} />
        <SelectDropdown
          icon={<FormatListBulletedOutlinedIcon sx={{ fontSize: 15 }} />}
          label="상태"
          options={REASON_FILTERS.map((entry) => ({ value: entry.label, label: entry.label }))}
          value={reasonLabel}
          onChange={setReasonLabel}
        />
        <SortDropdown value={order} onChange={(next) => setOrder(next as "asc" | "desc")} />
      </ViewHeader>
      {error ? (
        <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--danger)", fontSize: 13 }}>{error}</div>
      ) : !loading && !rows.length ? (
        <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>
          검색·유형·기간 조건에 일치하는 변경 기록 없음
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", opacity: loading ? 0.55 : 1, transition: "opacity .12s ease" }}>
          <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 12px 4px" }}>
            {rows.map((row, index) => {
              const stableKey = rowId(row);
              const bookmarked = bookmarkedRowids?.has(stableKey) ?? false;
              const meta = reasonMeta(row.reason || "");
              const Icon = meta.icon;
              const displayName = row.renamed_from
                ? `${row.renamed_from} → ${row.filename}`
                : row.filename;
              const memberCount = Number(row.group_count) || 0;
              return (
                <div
                  key={stableKey || `${safePage}-${index}`}
                  className={bookmarked ? "dfir-bookmarked-row" : undefined}
                  style={{ borderRadius: "var(--radius-md)", minHeight: 56, marginBottom: 8, display: "flex", alignItems: "center", gap: 12, padding: "0 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", color: "var(--text)", transition: "background .15s ease, border-color .15s ease" }}
                  onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}
                >
                  <div
                    role="button"
                    tabIndex={0}
                    aria-label={`${row.filename || "USN 기록"} 상세 보기`}
                    onClick={() => setDetail(row)}
                    onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setDetail(row); } }}
                    style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, padding: "9px 0", cursor: "pointer", outlineOffset: -3 }}
                  >
                    <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${meta.tone} 15%, transparent)` }}>
                      <Icon sx={{ fontSize: 17, color: meta.tone }} />
                    </span>
                    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                      <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 7, overflow: "hidden" }}>
                        <span title={displayName || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 13, fontWeight: 700, fontFamily: "var(--mono)" }}>{displayName || "파일명 없음"}</span>
                        <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: meta.tone, border: `1px solid ${meta.tone}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{meta.label}</span>
                        {memberCount > 1 && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11 }}>기록 {memberCount}건</span>}
                      </span>
                      <span title={row.reason || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.reason || "-"}</span>
                    </span>
                    <span title={`MFT 엔트리 ${row.mft_entry || "-"}`} style={{ width: 96, flexShrink: 0, textAlign: "right", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>#{row.mft_entry || "-"}</span>
                    <span style={{ width: 172, flexShrink: 0, textAlign: "right", color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>{row.timestamp || "시간 정보 없음"}</span>
                  </div>
                  <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}>
                    <span>
                      <IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "북마크"} disabled={!onToggleBookmark} size="small" onClick={() => onToggleBookmark?.(rowId(row))} sx={{ color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius-sm)" }}>
                        {bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 17 }} />}
                      </IconButton>
                    </span>
                  </Tooltip>
                </div>
              );
            })}
          </div>
          <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "6px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>
            <PaginationControls
              ariaLabel="USN 저널 페이지"
              page={safePage}
              pageCount={pageCount}
              onChange={setPage}
              summary={total ? `(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, total).toLocaleString()} / ${total.toLocaleString()})` : ""}
            />
          </div>
        </div>
      )}
      {detail && (
        <RowDetailPanel
          row={detail}
          columns={data?.columns ?? []}
          focusedColumn={null}
          fileBaseName="UsnJrnl_Records"
          onClose={() => setDetail(null)}
          onNavigate={() => {}}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(rowId(detail)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowId(detail)) : undefined}
        />
      )}
    </div>
  );
}
