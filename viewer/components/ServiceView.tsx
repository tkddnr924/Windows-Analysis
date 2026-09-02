"use client";
import MiscellaneousServicesOutlinedIcon from "@mui/icons-material/MiscellaneousServicesOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, rangeActive, type TimeRange } from "@/lib/timeRange";
import PaginationControls from "@/components/PaginationControls";
import RowDetailPanel from "./RowDetailPanel";

// Service Control Manager 이벤트를 서비스 단위로 묶어 읽는 뷰. 한 서비스가
// 카드 하나이고, 설치·시작 유형 변경·상태 변경·실패가 그 카드의 이력이 된다.
// 상태 변경(7036)만 호스트당 수만 건이 나오므로 카드 안의 원본 이벤트도
// 페이지 단위로만 그린다 — 펼친 카드 하나가 화면을 멈추게 하지 않는다.

const TABLE = "ServiceHistory";
// 목록·상세 페이지네이션은 앱 전체에서 10건 고정이다.
const PAGE = 10;
const EVENT_PAGE = 10;
const RESULT_COLOR: Record<string, string> = {
  실패: "var(--danger)",
};

interface Row {
  __rowid?: number;
  timestamp?: string;
  service_name?: string;
  service_key?: string;
  image_path?: string;
  account?: string;
  description?: string;
  state?: string;
  start_type_before?: string;
  start_type_after?: string;
  service_type?: string;
  detail?: string;
  result?: string;
  event_id?: string;
  record_key?: string;
}

interface Service {
  key: string;
  name: string;
  imagePath: string;
  installs: number;
  startTypeChanges: number;
  stateChanges: number;
  failures: number;
  first: string;
  last: string;
  events: Row[];
}

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

export default function ServiceView({
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
}: Props) {
  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("전체");
  const [sortDir, setSortDir] = useState("asc");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // 펼친 카드별 이벤트 페이지 — 서비스 하나가 수만 건일 수 있다.
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(TABLE);
  const rangeOn = rangeActive(timeRange);

  const services = useMemo(() => {
    const byKey = new Map<string, Service>();
    for (const raw of data.rows as Row[]) {
      const timestamp = raw.timestamp ?? "";
      if (!inRange(timestamp, timeRange)) continue;
      // 서비스 이름이 없는 기록(부팅 드라이버 로드 실패)은 이름 대신 그
      // 기록 종류로 묶는다 — 이름 없는 카드 한 덩어리로 뭉치지 않게.
      const name = raw.service_name || "";
      const key = name || raw.description || "(서비스 정보 없음)";
      const service = byKey.get(key) ?? {
        key,
        name,
        imagePath: "",
        installs: 0,
        startTypeChanges: 0,
        stateChanges: 0,
        failures: 0,
        first: timestamp,
        last: timestamp,
        events: [],
      };
      if (!byKey.has(key)) byKey.set(key, service);

      if (!service.imagePath && raw.image_path) service.imagePath = raw.image_path;
      if (raw.event_id === "7045") service.installs += 1;
      else if (raw.event_id === "7040") service.startTypeChanges += 1;
      else if (raw.event_id === "7036") service.stateChanges += 1;
      if (raw.result === "실패") service.failures += 1;
      if (timestamp) {
        if (!service.first || timestamp < service.first) service.first = timestamp;
        if (!service.last || timestamp > service.last) service.last = timestamp;
      }
      service.events.push(raw);
    }
    for (const service of byKey.values()) {
      service.events.sort((a, b) => (a.timestamp ?? "").localeCompare(b.timestamp ?? ""));
    }
    return [...byKey.values()];
  }, [data.rows, timeRange]);

  const kinds = useMemo(() => {
    const seen: string[] = [];
    for (const raw of data.rows as Row[]) {
      const kind = raw.description ?? "";
      if (kind && !seen.includes(kind)) seen.push(kind);
    }
    return seen.sort();
  }, [data.rows]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = services.filter((service) => {
      if (kindFilter !== "전체" && !service.events.some((e) => e.description === kindFilter)) return false;
      if (q && ![service.name, service.imagePath, service.key].some((v) => v.toLowerCase().includes(q))) return false;
      return true;
    });
    return filtered.sort((a, b) => {
      const c = (a.first || "").localeCompare(b.first || "");
      return sortDir === "asc" ? c : -c;
    });
  }, [services, query, kindFilter, sortDir]);

  const pageCount = Math.max(1, Math.ceil(shown.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageServices = shown.slice(safePage * PAGE, (safePage + 1) * PAGE);
  const eventTotal = useMemo(() => services.reduce((sum, s) => sum + s.events.length, 0), [services]);

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader
        icon={MiscellaneousServicesOutlinedIcon}
        title="서비스 이력"
        meta={`서비스 ${shown.length.toLocaleString()}개 · ${eventTotal.toLocaleString()}건`}
        right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? "전역 기간 필터 적용" : "전체 기간"}</span>}
      >
        <HeaderSearchInput value={query} onChange={(value) => { setQuery(value); setPage(0); }} placeholder="서비스 이름 · 경로 검색" width={300} />
        <SortDropdown value={sortDir} onChange={(next) => { setSortDir(next); setPage(0); }} />
        {kinds.length > 1 && (
          <SelectDropdown
            icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />}
            label="유형"
            options={["전체", ...kinds].map((kind) => ({
              value: kind,
              label: kind,
              count: kind === "전체" ? services.length : services.filter((s) => s.events.some((e) => e.description === kind)).length,
            }))}
            value={kindFilter}
            onChange={(next) => { setKindFilter(next); setPage(0); }}
          />
        )}
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {shown.length === 0 ? (
          <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
            {services.length === 0 ? "기간 내 서비스 이력이 없습니다." : "검색 또는 필터 조건에 맞는 서비스가 없습니다."}
          </div>
        ) : pageServices.map((service) => {
          const open = expanded.has(service.key);
          // 카드 색은 실패 기록이 있을 때만 신호를 준다 — 설치·상태 변경은
          // 그 자체로 위험도를 뜻하지 않으므로 중립색을 유지한다.
          const tone = service.failures > 0 ? "var(--danger)" : "var(--text-dim)";
          const eventPage = Math.min(eventPages[service.key] ?? 0, Math.max(0, Math.ceil(service.events.length / EVENT_PAGE) - 1));
          const eventPageCount = Math.max(1, Math.ceil(service.events.length / EVENT_PAGE));
          const pagedEvents = service.events.slice(eventPage * EVENT_PAGE, (eventPage + 1) * EVENT_PAGE);
          const sameDay = service.first.slice(0, 10) === service.last.slice(0, 10);
          return (
            <section key={service.key} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${tone} 42%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden", transition: "border-color .18s ease" }}>
              <button
                type="button"
                onClick={() => toggle(service.key)}
                aria-expanded={open}
                aria-label={`${service.key} 서비스 이벤트 ${service.events.length}건 ${open ? "접기" : "펼치기"}`}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .18s ease", outlineOffset: -2 }}
                onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent"; }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${tone} 15%, transparent)` }}>
                  <MiscellaneousServicesOutlinedIcon sx={{ fontSize: 17, color: tone }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700, color: "var(--text)" }}>{service.key}</span>
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    <span title={service.imagePath || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", color: service.imagePath ? "var(--text-dim)" : "var(--text-faint)" }}>{service.imagePath || "설치 기록 없음 (실행 파일 경로 미기록)"}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {service.events.length.toLocaleString()}건</span>
                  </span>
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0, fontSize: 12 }}>
                  {service.installs > 0 && <CountPill color="var(--text-dim)">설치 {service.installs.toLocaleString()}</CountPill>}
                  {service.startTypeChanges > 0 && <CountPill color="var(--text-dim)">시작 유형 {service.startTypeChanges.toLocaleString()}</CountPill>}
                  {service.stateChanges > 0 && <CountPill color="var(--text-dim)">상태 {service.stateChanges.toLocaleString()}</CountPill>}
                  {service.failures > 0 && <CountPill color="var(--danger)">실패 {service.failures.toLocaleString()}</CountPill>}
                </span>
                <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {service.first ? (<>{service.first} <span style={{ color: "var(--text-faint)" }}>→</span> {sameDay ? service.last.slice(11) : service.last}</>) : "시간 정보 없음"}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div role="region" aria-label={`원본 이벤트 ${service.events.length}건`} style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {pagedEvents.map((event, index) => {
                    const rowid = Number((event as Record<string, unknown>).__rowid);
                    const bookmarked = Number.isFinite(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                    const resultColor = RESULT_COLOR[event.result ?? ""] ?? "var(--text-faint)";
                    const change = event.start_type_before && event.start_type_after ? `${event.start_type_before} → ${event.start_type_after}` : "";
                    const extra = [event.state, change, event.detail].filter(Boolean).join(" · ");
                    return (
                      <div key={`${rowid}-${event.timestamp}-${index}`} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ borderRadius: 0, display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", background: "transparent", transition: "background .15s ease" }} onMouseEnter={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "transparent"; }}>
                        <div role="button" tabIndex={0} onClick={() => setSelected(event as Record<string, string>)} onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") { keyboardEvent.preventDefault(); setSelected(event as Record<string, string>); } }} style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, color: "var(--text)", cursor: "pointer", outlineOffset: 2 }}>
                          <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{event.timestamp || "시간 정보 없음"}</span>
                          <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: resultColor }} />
                          <span style={{ flexShrink: 0, color: resultColor, fontSize: 12, fontWeight: 700, width: 34 }}>{event.result || "정보"}</span>
                          <span title={event.description || ""} style={{ width: 210, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 12.5 }}>{event.description || ""}</span>
                          <span title={extra || undefined} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: extra ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12 }}>{extra}</span>
                          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{event.event_id ? `EID ${event.event_id}` : ""}</span>
                        </div>
                        {onToggleBookmark && Number.isFinite(rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={() => onToggleBookmark(rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                      </div>
                    );
                  })}
                  {eventPageCount > 1 && (
                    <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "4px 0 6px" }}>
                      <PaginationControls
                        ariaLabel={`${service.key} 이벤트 페이지`}
                        page={eventPage}
                        pageCount={eventPageCount}
                        onChange={(next) => setEventPages((prev) => ({ ...prev, [service.key]: next }))}
                        summary={`(${(eventPage * EVENT_PAGE + 1).toLocaleString()}–${Math.min((eventPage + 1) * EVENT_PAGE, service.events.length).toLocaleString()} / ${service.events.length.toLocaleString()})`}
                      />
                    </div>
                  )}
                </div>
              )}
            </section>
          );
        })}
        {shown.length > 0 && (
          <PaginationControls
            ariaLabel="서비스 페이지"
            page={safePage}
            pageCount={pageCount}
            onChange={setPage}
            summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, shown.length).toLocaleString()} / ${shown.length.toLocaleString()})`}
          />
        )}
      </main>

      {selected && spec && (
        <RowDetailPanel
          row={selected}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName={TABLE}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined}
        />
      )}
    </div>
  );
}

function CountPill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ color, fontWeight: 700, padding: "1px 7px", borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${color} 15%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}
