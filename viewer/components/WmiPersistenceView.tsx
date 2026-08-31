"use client";
// WMI 이벤트 구독 뷰 — WMI_Persistence 테이블(바인딩·이벤트 필터·이벤트
// 컨슈머)을 findings 원장 형태로 보여준다. 이 아티팩트에는 시각 정보가
// 없으므로 기간·정렬 컨트롤 없이 검색 + 구분 필터만 둔다.
import { useEffect, useMemo, useRef, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import DeviceHubOutlinedIcon from "@mui/icons-material/DeviceHubOutlined";
import EventNoteOutlinedIcon from "@mui/icons-material/EventNoteOutlined";
import FilterAltOutlinedIcon from "@mui/icons-material/FilterAltOutlined";
import FormatListBulletedOutlinedIcon from "@mui/icons-material/FormatListBulletedOutlined";
import LinkOutlinedIcon from "@mui/icons-material/LinkOutlined";
import PlayCircleOutlineOutlinedIcon from "@mui/icons-material/PlayCircleOutlineOutlined";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";
import { HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import RowDetailPanel from "./RowDetailPanel";
import type { CsvData, WmiSubscriptionEvents } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, type TimeRange } from "@/lib/timeRange";

type Row = Record<string, string>;

interface Props {
  data: CsvData;
  /** WMI_Persistence.sqlite 경로 — 같은 호스트의 WMI-Activity 이벤트 로그를
   *  찾아 구독 이벤트(5859~5861)를 합류시키는 데 쓴다. */
  dbPath: string;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  /** 전역 기간 필터 — 시각이 있는 구독 이벤트 행에만 적용된다. */
  timeRange?: TimeRange;
  /** `${fullPath}#${rowid}` 키 — 구독 이벤트(원본 EventLog 행) 북마크 상태. */
  bookmarkedKeys?: Set<string>;
  /** 구독 이벤트는 원본 EventLog 행 기준으로 북마크한다. */
  onToggleEventBookmark?: (fullPath: string, tableName: string, rowid: number, eventTime?: string) => void;
}

const PAGE = 10;
const KIND_ALL = "전체";
const KIND_ORDER = ["바인딩", "이벤트 필터", "이벤트 컨슈머", "구독 이벤트"];
const KIND_META: Record<string, { icon: typeof LinkOutlinedIcon; tone: string }> = {
  바인딩: { icon: LinkOutlinedIcon, tone: "var(--accent)" },
  "이벤트 필터": { icon: FilterAltOutlinedIcon, tone: "var(--success)" },
  "이벤트 컨슈머": { icon: PlayCircleOutlineOutlinedIcon, tone: "var(--warning)" },
  // WMI-Activity 이벤트 로그의 구독 이벤트 — OBJECTS.DATA 추출과 달리 시각이 있다.
  "구독 이벤트": { icon: EventNoteOutlinedIcon, tone: "#7490e2" },
};
const EVENTLOG_FILE = "Microsoft-Windows-WMI-Activity%4Operational";
// 구독 관련 EventID와 기능 명칭 (5857/5858 등 일반 동작 기록은 제외).
const SUB_EVENT_LABELS: Record<string, string> = {
  "5859": "필수 이벤트 필터 활성",
  "5860": "임시 이벤트 구독",
  "5861": "영구 이벤트 구독 등록",
};

/// 표시 행 하나 — WMI_Persistence 행이거나 이벤트 로그에서 온 구독 이벤트.
interface DisplayEntry {
  key: string;
  display: Row;
  detailRow: Row;
  detailColumns: string[];
  detailFile: string;
  /** WMI_Persistence 행은 이 파일 rowid로, 구독 이벤트는 원본 EventLog 행으로 북마크한다. */
  bookmarkable: boolean;
  /** 구독 이벤트의 원본 위치 — 비어 있으면 WMI_Persistence 행. */
  eventFullPath?: string;
  eventTableName?: string;
  timestamp: string;
}

/// EventData JSON에서 래퍼(Operation_...) 안의 필드를 꺼낸다.
function subEventFields(raw: string): Record<string, string> {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const wrapper = Object.values(parsed).find((value) => typeof value === "object" && value !== null);
    if (!wrapper) return {};
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(wrapper as Record<string, unknown>)) {
      if (typeof value === "string" || typeof value === "number") out[key] = String(value);
    }
    return out;
  } catch {
    return {};
  }
}

function rowId(row: Row): number {
  return Number((row as Record<string, unknown>).__rowid);
}

/// 행의 둘째 줄 — 구분별로 분석가가 가장 먼저 볼 값.
function rowSummary(row: Row): string {
  if (row.kind === "이벤트 필터") return row.query || "";
  if (row.kind === "이벤트 컨슈머") return row.details || "";
  if (row.kind === "구독 이벤트") return row.details || "";
  return row.filter_name && row.consumer_name ? `${row.filter_name} → ${row.consumer_name}` : "";
}

function rowSideLabel(row: Row): string {
  if (row.kind === "구독 이벤트") return row.timestamp || "";
  if (row.kind === "이벤트 필터") return row.namespace || row.query_language || "";
  return row.consumer_type || "";
}

export default function WmiPersistenceView({ data, dbPath, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, bookmarkedKeys, onToggleEventBookmark }: Props) {
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState(KIND_ALL);
  const [detail, setDetail] = useState<DisplayEntry | null>(null);
  const [page, setPage] = useState(0);
  const [eventLog, setEventLog] = useState<WmiSubscriptionEvents | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // 같은 호스트의 WMI-Activity 이벤트 로그에서 구독 이벤트(5859~5861)만
  // 서버에서 걸러 받는다 — 원본 로그 전체를 웹뷰로 가져오지 않는다.
  // 로그가 없는 호스트면 조용히 건너뛴다.
  useEffect(() => {
    let cancelled = false;
    setEventLog(null);
    const parts = dbPath.split(/[\\/]/);
    const hostDir = parts.slice(0, Math.max(0, parts.length - 2)).join("/");
    if (!hostDir) return;
    window.api
      .wmiSubscriptionEvents(hostDir)
      .then((result) => {
        if (!cancelled) setEventLog(result);
      })
      .catch(() => {
        if (!cancelled) setEventLog(null);
      });
    return () => {
      cancelled = true;
    };
  }, [dbPath]);

  const entries = useMemo<DisplayEntry[]>(() => {
    const persisted = (data.rows as Row[]).map((row, index) => ({
      key: `wmi-${(row as Record<string, unknown>).__rowid ?? index}`,
      display: row,
      detailRow: row,
      detailColumns: data.columns,
      detailFile: "WMI_Persistence",
      bookmarkable: true,
      timestamp: "",
    }));
    const events: DisplayEntry[] = [];
    for (const row of (eventLog?.rows ?? []) as Row[]) {
      const label = SUB_EVENT_LABELS[row.EventID || ""];
      if (!label) continue;
      // 전역 기간 필터 — 시각이 있는 구독 이벤트에만 적용한다 (OBJECTS.DATA
      // 추출 항목은 시각이 없어 대상 밖).
      if (!inRange(row.timestamp || "", timeRange)) continue;
      const fields = subEventFields(row.EventData || "");
      const query = fields.Query || fields.ESS || "";
      const consumer = fields.CONSUMER || "";
      const parts = [query, consumer && `→ ${consumer}`, fields.ClientMachine && `장치 ${fields.ClientMachine}`, fields.User && `계정 ${fields.User}`].filter(Boolean);
      events.push({
        key: `evt-${(row as Record<string, unknown>).__rowid ?? events.length}`,
        display: {
          kind: "구독 이벤트",
          name: label,
          consumer_type: "",
          filter_name: "",
          consumer_name: consumer,
          query,
          query_language: "",
          namespace: fields.NamespaceName || fields.Namespace || "",
          details: parts.join(" · "),
          timestamp: row.timestamp || "",
        },
        detailRow: row,
        detailColumns: eventLog?.columns ?? [],
        detailFile: EVENTLOG_FILE,
        // 원본 EventLog 행 기준 북마크 — 다른 뷰(통합 타임라인 등)와 공유된다.
        bookmarkable: !!eventLog?.fullPath,
        eventFullPath: eventLog?.fullPath,
        eventTableName: eventLog?.tableName,
        timestamp: row.timestamp || "",
      });
    }
    events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return [...persisted, ...events];
  }, [data.rows, data.columns, eventLog, timeRange]);

  const kinds = useMemo(() => {
    const present = new Set(entries.map((entry) => entry.display.kind || ""));
    return KIND_ORDER.filter((kind) => present.has(kind));
  }, [entries]);
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return entries.filter((entry) => {
      const row = entry.display;
      if (kindFilter !== KIND_ALL && (row.kind || "") !== kindFilter) return false;
      return (
        !needle ||
        [row.name, row.filter_name, row.consumer_name, row.consumer_type, row.query, row.namespace, row.details].some(
          (value) => (value || "").toLowerCase().includes(needle),
        )
      );
    });
  }, [entries, kindFilter, search]);
  useEffect(() => {
    setPage(0);
    scrollRef.current?.scrollTo({ top: 0 });
  }, [rows]);

  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = rows.slice(safePage * PAGE, (safePage + 1) * PAGE);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <ViewHeader
        icon={DeviceHubOutlinedIcon}
        title="WMI 이벤트 구독"
        meta={`${rows.length.toLocaleString()}건${rows.length !== entries.length ? ` / 전체 ${entries.length.toLocaleString()}건` : ""}`}
      >
        <HeaderSearchInput value={search} onChange={setSearch} placeholder="이름 · 쿼리 · 명령 검색" ariaLabel="WMI 구독 검색" width={300} />
        {kinds.length > 1 && (
          <SelectDropdown
            icon={<FormatListBulletedOutlinedIcon sx={{ fontSize: 15 }} />}
            label="구분"
            options={[KIND_ALL, ...kinds].map((kind) => ({ value: kind, label: kind }))}
            value={kindFilter}
            onChange={setKindFilter}
          />
        )}
      </ViewHeader>
      {data.rows.length > 0 && (
        // WMI 저장소 항목은 시그니처 스캔 단서다 — 저장소 특성상 과거 제거된
        // 구독의 잔존 데이터가 섞일 수 있어, 현재 활성으로 단정하지 않도록
        // 성격을 화면에 고지한다 (2026-08-31 사용자 확정 방향).
        <div style={{ flexShrink: 0, padding: "7px 16px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontSize: 11.5 }}>
          바인딩 · 이벤트 필터 · 이벤트 컨슈머 항목은 WMI 저장소(OBJECTS.DATA) 스캔에서 복원한 단서로, 현재 활성 여부는 보장되지 않습니다 — 과거 제거된 구독의 잔존 기록이 포함될 수 있습니다. 구독 이벤트 항목(이벤트 로그)과 교차 확인하세요.
        </div>
      )}
      {!rows.length ? (
        <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>
          {entries.length === 0 ? "추출된 WMI 이벤트 구독이 없습니다." : "검색·구분 조건에 일치하는 항목 없음"}
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 12px 4px" }}>
            {pageRows.map((entry) => {
              const row = entry.display;
              const stableKey = rowId(entry.detailRow);
              const isEvent = !!entry.eventFullPath;
              const canBookmark = entry.bookmarkable && (isEvent ? !!onToggleEventBookmark : !!onToggleBookmark);
              const bookmarked = entry.bookmarkable && (isEvent
                ? (bookmarkedKeys?.has(`${entry.eventFullPath}#${stableKey}`) ?? false)
                : (bookmarkedRowids?.has(stableKey) ?? false));
              const toggleBookmark = (clickEvent: React.MouseEvent) => {
                clickEvent.stopPropagation();
                if (isEvent) onToggleEventBookmark?.(entry.eventFullPath!, entry.eventTableName || "", stableKey, entry.timestamp || undefined);
                else onToggleBookmark?.(stableKey);
              };
              const meta = KIND_META[row.kind] ?? { icon: DeviceHubOutlinedIcon, tone: "var(--text-dim)" };
              const Icon = meta.icon;
              const summary = rowSummary(row);
              const side = rowSideLabel(row);
              return (
                <div
                  key={entry.key}
                  className={bookmarked ? "dfir-bookmarked-row" : undefined}
                  // 행 전체(여백 포함)가 상세 열기 클릭 대상 — 북마크는 전파 차단.
                  onClick={() => setDetail(entry)}
                  style={{ borderRadius: "var(--radius-md)", minHeight: 62, marginBottom: 8, display: "flex", alignItems: "center", gap: 12, padding: "0 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", color: "var(--text)", cursor: "pointer", transition: "background .15s ease, border-color .15s ease" }}
                  onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}
                >
                  <div
                    role="button"
                    tabIndex={0}
                    aria-label={`${row.name || "WMI 구독 항목"} 상세 보기`}
                    onClick={() => setDetail(entry)}
                    onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setDetail(entry); } }}
                    style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, padding: "10px 0", cursor: "pointer", outlineOffset: -3 }}
                  >
                    <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${meta.tone} 15%, transparent)` }}>
                      <Icon sx={{ fontSize: 17, color: meta.tone }} />
                    </span>
                    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                      <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 7, overflow: "hidden" }}>
                        <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 13.5, fontWeight: 700 }}>{row.name || "이름 정보 없음"}</span>
                        <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: meta.tone, border: `1px solid ${meta.tone}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{row.kind || "정보"}</span>
                      </span>
                      <span title={summary || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: summary ? "var(--text-dim)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12 }}>{summary || "세부 값 없음"}</span>
                    </span>
                    <span title={side || undefined} style={{ width: 220, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "right", color: side ? (row.kind === "구독 이벤트" ? "var(--text-time)" : "var(--text-dim)") : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{side || "-"}</span>
                  </div>
                  {canBookmark && (
                    <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}>
                      <span>
                        <IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "북마크"} size="small" onClick={toggleBookmark} sx={{ color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius-sm)" }}>
                          {bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 17 }} />}
                        </IconButton>
                      </span>
                    </Tooltip>
                  )}
                </div>
              );
            })}
          </div>
          <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "6px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>
            <PaginationControls
              ariaLabel="WMI 구독 페이지"
              page={safePage}
              pageCount={pageCount}
              onChange={(next) => { setPage(next); scrollRef.current?.scrollTo({ top: 0 }); }}
              summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, rows.length).toLocaleString()} / ${rows.length.toLocaleString()})`}
            />
          </div>
        </div>
      )}
      {detail && (
        <RowDetailPanel
          row={detail.detailRow}
          columns={detail.detailColumns}
          focusedColumn={null}
          fileBaseName={detail.detailFile}
          onClose={() => setDetail(null)}
          onNavigate={() => {}}
          isBookmarked={detail.bookmarkable
            ? detail.eventFullPath
              ? bookmarkedKeys?.has(`${detail.eventFullPath}#${rowId(detail.detailRow)}`) ?? false
              : onToggleBookmark ? bookmarkedRowids?.has(rowId(detail.detailRow)) ?? false : undefined
            : undefined}
          onToggleBookmark={detail.bookmarkable
            ? detail.eventFullPath
              ? onToggleEventBookmark
                ? () => onToggleEventBookmark(detail.eventFullPath!, detail.eventTableName || "", rowId(detail.detailRow), detail.timestamp || undefined)
                : undefined
              : onToggleBookmark ? () => onToggleBookmark(rowId(detail.detailRow)) : undefined
            : undefined}
        />
      )}
    </div>
  );
}
