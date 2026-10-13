"use client";
// USN 저널 뷰 (docs-05) — _OVERVIEW/UsnJournal의 저장된 변경 묶음
// (UsnChangeGroups)을 목록 단위로 보여 준다. 묶음을 펼치면 모든 구성 기록이
// 저장 순서대로 나오고, 검색·변경 이유·기간에 맞은 기록만 표시된다. 대표 한
// 행을 묶음 전체의 근거로 쓰지 않으며, 입력($J)은 근거 없이 합치지 않는다.
import AppLoader from "@/components/AppLoader";
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
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import TuneOutlinedIcon from "@mui/icons-material/TuneOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import RowDetailPanel from "./RowDetailPanel";
import type { UsnGroupEntry, UsnGroupsPage, UsnOverview, UsnRenameEntry } from "@/lib/types";
import { toBound, type TimeRange } from "@/lib/timeRange";
import { volumeLabels } from "@/lib/mftVolumeLabels";
import { ambiguityLabels, candidateSides, groupHeadline, matchedCount, reasonFlags, renameStatusLabel } from "@/lib/usnJournal";

type Row = Record<string, string>;

interface Props {
  dbPath: string;
  timeRange?: TimeRange;
  /** Bookmark state of the source record a member points at (never the group). */
  isRowBookmarked?: (row: Row) => boolean;
  onToggleBookmark?: (rowid: number) => void;
}

/** Existing page size (docs-24 §2). */
const PAGE = 10;
// Reason flag → tone (stored flag names only).
function flagTone(flag: string): string {
  if (flag === "FILE_CREATE") return "var(--success)";
  if (flag === "FILE_DELETE") return "var(--danger)";
  if (flag.startsWith("RENAME_")) return "var(--accent)";
  if (flag.startsWith("DATA_") || flag.startsWith("NAMED_DATA_")) return "var(--warning)";
  return "var(--text-faint)";
}

/** First non-CLOSE flag decides the dot colour. */
function memberTone(reason: string | undefined): string {
  const flags = reasonFlags(reason);
  return flagTone(flags.find((flag) => flag !== "CLOSE") ?? flags[0] ?? "");
}

function MemberRow({ member, previous, groupDate, selected, bookmarked, onToggleBookmark, onSelect }: {
  member: Row;
  previous: Row | null;
  groupDate: string;
  selected: boolean;
  bookmarked: boolean;
  onToggleBookmark?: (rowid: number) => void;
  onSelect: (row: Row) => void;
}) {
  const [hover, setHover] = useState(false);
  const [focused, setFocused] = useState(false);
  const hit = member.__matched === "true";
  const time = member.timestamp ?? "";
  // The card header carries the date; repeat it only when it changes.
  const shownTime = !time ? "—" : time.slice(0, 10) === groupDate ? time.slice(11) : time;
  const sameName = previous !== null && previous.file_name === member.file_name;
  const tone = memberTone(member.reason);
  return (
    <li
      tabIndex={0}
      aria-label={`${member.file_name || "기록"} 상세 보기`}
      onClick={() => onSelect(member)}
      // Only the row itself opens detail; keys on the bookmark button stay its own.
      onKeyDown={(event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); onSelect(member); } }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onFocus={() => setFocused(true)}
      onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setFocused(false); }}
      style={{ position: "relative", display: "grid", gridTemplateColumns: "88px 14px minmax(0, 1fr) auto", alignItems: "center", columnGap: 10, minHeight: 34, padding: "3px 8px", borderRadius: 8, cursor: "pointer", outlineOffset: -2, background: selected ? "var(--bg-selected)" : hover ? "var(--bg-hover)" : hit ? "color-mix(in srgb, var(--accent) 8%, transparent)" : "transparent", transition: "background .12s ease" }}
    >
      <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, fontVariantNumeric: "tabular-nums", color: time ? "var(--text-time)" : "var(--text-faint)", textAlign: "right", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={time || undefined}>{shownTime}</span>
      <span aria-hidden="true" style={{ justifySelf: "center", width: 9, height: 9, borderRadius: "50%", background: hit ? tone : "var(--bg-panel)", border: `2px solid ${tone}`, boxShadow: hit ? `0 0 0 3px color-mix(in srgb, ${tone} 25%, transparent)` : "none", zIndex: 1 }} />
      <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 8, overflow: "hidden" }}>
        <span title={member.file_name} style={{ minWidth: 0, flexShrink: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: hit ? 700 : 550, color: sameName ? "var(--text-faint)" : "var(--text)" }}>{member.file_name || "(이름 없음)"}</span>
        {member.rename_role && <span style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, letterSpacing: 0.3, color: "var(--accent)", background: "var(--accent-subtle)", borderRadius: 999, padding: "1px 7px" }}>{member.rename_role === "old" ? "OLD" : member.rename_role === "new" ? "NEW" : "OLD·NEW"}</span>}
        <span style={{ display: "flex", gap: 4, flexShrink: 0 }}>
          {reasonFlags(member.reason).map((flag) => {
            const flagColor = flagTone(flag);
            return <span key={flag} style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: flagColor, background: `color-mix(in srgb, ${flagColor} 12%, transparent)`, borderRadius: 4, padding: "1px 6px", whiteSpace: "nowrap" }}>{flag}</span>;
          })}
        </span>
      </span>
      <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)", opacity: hover || focused || selected ? 1 : 0.6 }}>USN {member.usn || "-"}</span>
        <IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "이 기록 북마크"} disabled={!onToggleBookmark} size="small" onClick={(event) => { event.stopPropagation(); onToggleBookmark?.(rowId(member)); }} sx={{ p: 0.5, opacity: bookmarked || hover || focused || selected ? 1 : 0, transition: "opacity .12s ease", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius)" }}>
          {bookmarked ? <BookmarkIcon sx={{ fontSize: 15 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 15 }} />}
        </IconButton>
      </span>
    </li>
  );
}
const ALL = "";

// Representative type (stored Korean label) → icon and tone.
function typeMeta(eventType: string | undefined): { icon: typeof HistoryOutlinedIcon; tone: string } {
  const type = eventType ?? "";
  if (type === "삭제") return { icon: DeleteOutlineOutlinedIcon, tone: "var(--danger)" };
  if (type === "생성") return { icon: AddCircleOutlineOutlinedIcon, tone: "var(--success)" };
  if (type.startsWith("이름 변경")) return { icon: DriveFileRenameOutlineOutlinedIcon, tone: "var(--accent)" };
  if (type === "내용 변경") return { icon: EditNoteOutlinedIcon, tone: "var(--warning)" };
  if (type === "속성 변경" || type === "보안 변경" || type === "스트림 변경") return { icon: DescriptionOutlinedIcon, tone: "var(--text-dim)" };
  return { icon: HistoryOutlinedIcon, tone: "var(--text-faint)" };
}

function rowId(row: Row): number {
  return Number(row.__rowid);
}

/** Same-day end time shows only the clock. */
function timeSpan(first: string | undefined, last: string | undefined): { first: string; last: string } {
  if (!first) return { first: "시간 정보 없음", last: "" };
  if (!last || last === first) return { first, last: "" };
  return { first, last: last.slice(0, 10) === first.slice(0, 10) ? last.slice(11) : last };
}

export default function UsnJrnlView({ dbPath, timeRange, isRowBookmarked, onToggleBookmark }: Props) {
  const [overview, setOverview] = useState<UsnOverview | null>(null);
  const [inputId, setInputId] = useState(ALL);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [eventType, setEventType] = useState(ALL);
  const [flags, setFlags] = useState<string[]>([]);
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  // Page is tied to the filter set it was chosen under; a new set starts at 0
  // in the same render, so no request goes out with a stale offset.
  const [pageState, setPageState] = useState<{ key: string; page: number }>({ key: "", page: 0 });
  const [data, setData] = useState<UsnGroupsPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [optionsError, setOptionsError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [detail, setDetail] = useState<Row | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const requestSeq = useRef(0);

  // Inputs first; the first input is selected — inputs are never merged.
  useEffect(() => {
    let alive = true;
    window.api.usnOverview(dbPath).then((result) => {
      if (!alive) return;
      setOverview(result);
      setInputId((current) => current || result.inputs[0]?.input_id || ALL);
      if (!result.inputs.length) setLoading(false);
    }).catch((e) => { if (alive) setError(String(e)); });
    return () => { alive = false; };
  }, [dbPath]);
  // Filter options are counted per input.
  useEffect(() => {
    if (!inputId) return;
    let alive = true;
    setOptionsError(null);
    window.api.usnOverview(dbPath, inputId).then((result) => { if (alive) setOverview(result); }).catch((e) => {
      if (!alive) return;
      // Never keep the previous input's options.
      setOverview((current) => current && { ...current, eventTypes: [], reasonFlags: [] });
      setOptionsError(String(e));
    });
    return () => { alive = false; };
  }, [dbPath, inputId]);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim()), 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  const start = toBound(timeRange?.start ?? "", "start");
  const end = toBound(timeRange?.end ?? "", "end");
  const filterKey = JSON.stringify([dbPath, inputId, debouncedSearch, eventType, flags, order, start, end]);
  const page = pageState.key === filterKey ? pageState.page : 0;
  const setPage = (next: number) => setPageState({ key: filterKey, page: next });
  useEffect(() => { setExpanded(new Set()); }, [filterKey]);

  useEffect(() => {
    if (!inputId) return;
    const seq = ++requestSeq.current;
    setLoading(true);
    window.api
      .usnGroupsPage(dbPath, {
        inputId,
        search: debouncedSearch || undefined,
        eventType: eventType || undefined,
        reasonFlags: flags.length ? flags : undefined,
        timeStart: start || undefined,
        timeEnd: end || undefined,
        descending: order === "desc",
      }, page * PAGE, PAGE)
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
    // filterKey stands for every filter value read above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey, page]);

  const inputLabels = useMemo(
    () => volumeLabels((overview?.inputs ?? []).map((input) => ({ volume_id: input.input_id, volume_label: null, drive_letter: null, input_name: input.input_name, source_relative: input.source_relative, record_count: String(input.record_count) }))),
    [overview],
  );
  const groups = data?.groups ?? [];
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const memberFiltered = Boolean(debouncedSearch || flags.length || start || end);
  const toggle = (id: string) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <ViewHeader
        icon={HistoryOutlinedIcon}
        title="USN 저널"
        meta={`묶음 ${total.toLocaleString()}건`}
        right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{start || end ? "기간 필터 적용 (구성 기록 시각)" : "전체 기간"}</span>}
      >
        {optionsError && <span role="status" title={optionsError} style={{ color: "var(--warning)", fontSize: 11.5 }}>필터 옵션을 읽지 못했습니다</span>}
        <HeaderSearchInput value={search} onChange={setSearch} placeholder="파일명·변경 이유 검색" ariaLabel="USN 저널 검색" width={260} />
        <SelectDropdown
          icon={<StorageOutlinedIcon sx={{ fontSize: 15 }} />}
          label="입력"
          options={(overview?.inputs ?? []).map((input) => ({ value: input.input_id, label: inputLabels[input.input_id] ?? input.input_id }))}
          value={inputId}
          defaultValue={overview?.inputs[0]?.input_id}
          onChange={setInputId}
        />
        <SelectDropdown
          icon={<FormatListBulletedOutlinedIcon sx={{ fontSize: 15 }} />}
          label="대표 유형"
          options={[{ value: ALL, label: "전체" }, ...(overview?.eventTypes ?? []).map((option) => ({ value: option.value, label: option.value, count: option.count }))]}
          value={eventType}
          defaultValue={ALL}
          onChange={setEventType}
        />
        <MultiSelectDropdown
          icon={<TuneOutlinedIcon sx={{ fontSize: 15 }} />}
          label="변경 이유"
          options={(overview?.reasonFlags ?? []).map((option) => ({ value: option.value, label: option.value, count: option.count }))}
          selected={flags}
          onChange={setFlags}
        />
        <SortDropdown value={order} onChange={(next) => setOrder(next as "asc" | "desc")} />
      </ViewHeader>
      {error ? (
        <div role="alert" style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--danger)", fontSize: 13, padding: 16, textAlign: "center" }}>{error}</div>
      ) : loading && !groups.length ? (
        <div style={{ flex: 1, minHeight: 180, display: "grid", placeItems: "center" }}>
          <AppLoader message="USN 저널 기록을 불러오는 중" />
        </div>
      ) : !loading && !groups.length ? (
        <div role="status" style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>
          {overview && !overview.inputs.length ? "저장된 변경 묶음이 없습니다" : "검색·유형·변경 이유·기간 조건에 맞는 변경 묶음이 없습니다"}
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", opacity: loading ? 0.55 : 1, transition: "opacity .12s ease" }}>
          <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 12px 4px" }}>
            {groups.map((entry) => (
              <GroupCard
                key={entry.group.group_id}
                entry={entry}
                open={expanded.has(entry.group.group_id)}
                memberFiltered={memberFiltered}
                isRowBookmarked={isRowBookmarked}
                onToggleBookmark={onToggleBookmark}
                onToggle={() => toggle(entry.group.group_id)}
                onSelect={setDetail}
                selectedRowid={detail ? rowId(detail) : null}
              />
            ))}
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
          columns={Object.keys(detail).filter((key) => !key.startsWith("__"))}
          focusedColumn={null}
          fileBaseName="UsnJournal"
          onClose={() => setDetail(null)}
          onNavigate={() => {}}
          isBookmarked={onToggleBookmark ? isRowBookmarked?.(detail) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowId(detail)) : undefined}
        />
      )}
    </div>
  );
}

function GroupCard({ entry, open, memberFiltered, isRowBookmarked, onToggleBookmark, onToggle, onSelect, selectedRowid }: {
  entry: UsnGroupEntry;
  open: boolean;
  memberFiltered: boolean;
  isRowBookmarked?: (row: Row) => boolean;
  onToggleBookmark?: (rowid: number) => void;
  onToggle: () => void;
  onSelect: (row: Row) => void;
  selectedRowid: number | null;
}) {
  const { group, members, renames } = entry;
  const meta = typeMeta(group.event_type);
  const Icon = meta.icon;
  const headline = groupHeadline(entry);
  const flags = reasonFlags(group.reason_union);
  const matched = matchedCount(entry);
  const span = timeSpan(group.first_timestamp, group.last_timestamp);
  const anyBookmarked = members.some((member) => isRowBookmarked?.(member));
  const unsettled = renames.filter((rename) => rename.event.status && rename.event.status !== "paired");
  const regionId = `usn-group-${group.group_id}`;
  const chip: React.CSSProperties = { flexShrink: 0, fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--text-dim)", border: "1px solid var(--border-subtle)", borderRadius: 4, padding: "0 5px", whiteSpace: "nowrap" };

  return (
    <div className={anyBookmarked ? "dfir-bookmarked-row" : undefined} style={{ marginBottom: 8, borderRadius: "var(--radius)", border: `1px solid ${open ? "var(--border-strong, var(--border))" : "var(--border)"}`, background: "var(--bg-panel)", overflow: "hidden" }}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={regionId}
        aria-label={`${headline} 변경 묶음 ${open ? "접기" : "펼치기"}`}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 58, padding: "8px 14px", border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}
      >
        {open ? <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)" }} /> : <KeyboardArrowRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)" }} />}
        <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${meta.tone} 15%, transparent)` }}>
          <Icon sx={{ fontSize: 17, color: meta.tone }} />
        </span>
        <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 4 }}>
          <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 7, overflow: "hidden" }}>
            <span title={headline} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13, fontWeight: 700, fontFamily: "var(--mono)" }}>{headline}</span>
            {group.event_type && <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: meta.tone, border: `1px solid ${meta.tone}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{group.event_type}</span>}
            {unsettled.map((rename) => <span key={rename.event.rename_id} title={ambiguityLabels(rename.event.ambiguity_reason).join(", ") || undefined} style={{ flexShrink: 0, fontSize: 11, fontWeight: 650, color: "var(--warning)", whiteSpace: "nowrap" }}>이름 변경 {renameStatusLabel(rename.event.status)}</span>)}
            <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11 }}>기록 {Number(group.member_count || members.length).toLocaleString()}건</span>
            {memberFiltered && matched > 0 && <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 650, color: "var(--accent)" }}>일치 {matched}건</span>}
            {anyBookmarked && <BookmarkIcon aria-label="북마크한 기록 포함" sx={{ fontSize: 14, color: "var(--bookmark-control)", flexShrink: 0 }} />}
          </span>
          <span title={`전체 변경 이유: ${flags.join(" | ")}`} style={{ minWidth: 0, display: "flex", gap: 4, overflow: "hidden" }}>
            {flags.map((flag) => <span key={flag} style={chip}>{flag}</span>)}
          </span>
        </span>
        <span style={{ flexShrink: 0, display: "grid", justifyItems: "end", gap: 2, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums" }}>
          <span style={{ fontSize: 12, color: group.first_timestamp ? "var(--text-time)" : "var(--text-faint)", whiteSpace: "nowrap" }}>{span.first}</span>
          {span.last && <span style={{ fontSize: 11, color: "var(--text-faint)", whiteSpace: "nowrap" }}>~ {span.last}</span>}
        </span>
      </button>
      <div id={regionId} hidden={!open}>
        {open && (
          <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "10px 16px 12px 58px", display: "grid", gap: 10 }}>
            <ol aria-label="구성 기록" style={{ listStyle: "none", margin: 0, padding: 0, position: "relative" }}>
              <span aria-hidden="true" style={{ position: "absolute", left: 112, top: 17, bottom: 17, width: 1, background: "var(--border)" }} />
              {members.map((member, index) => (
                <MemberRow
                  key={member.record_id}
                  member={member}
                  previous={index > 0 ? members[index - 1] : null}
                  groupDate={(group.first_timestamp ?? "").slice(0, 10)}
                  selected={selectedRowid !== null && rowId(member) === selectedRowid}
                  bookmarked={isRowBookmarked?.(member) ?? false}
                  onToggleBookmark={onToggleBookmark}
                  onSelect={onSelect}
                />
              ))}
            </ol>
            {renames.map((rename) => (
              <RenameEvidence key={rename.event.rename_id} rename={rename} members={members} onSelect={onSelect} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/** Stored rename event with every OLD/NEW candidate (docs-05 §0/§1). The
 *  analyst sees the alternatives, not only the status label. */
function RenameEvidence({ rename, members, onSelect }: { rename: UsnRenameEntry; members: Row[]; onSelect: (row: Row) => void }) {
  const { event } = rename;
  const sides = candidateSides(rename);
  const reasons = ambiguityLabels(event.ambiguity_reason);
  const paired = event.status === "paired";
  const memberOf = new Map(members.map((member) => [member.record_id, member]));
  const column = (title: string, list: ReturnType<typeof candidateSides>["old"]) => (
    <div style={{ display: "grid", gap: 3, alignContent: "start", minWidth: 0 }}>
      <span style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)" }}>{title} · {list.length}개</span>
      {list.length === 0 ? <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>저장된 후보 없음</span> : list.map(({ candidate, representative }) => {
        const member = candidate.record_id ? memberOf.get(candidate.record_id) : undefined;
        const body = (
          <>
            <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
              <span title={candidate.file_name} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: representative ? 700 : 500 }}>{candidate.file_name || "(이름 없음)"}</span>
              {representative && <span style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, color: "var(--accent)" }}>대표</span>}
              {candidate.role === "both" && <span style={{ flexShrink: 0, fontSize: 10, color: "var(--text-faint)" }}>OLD·NEW</span>}
            </span>
            <span style={{ display: "flex", gap: 10, fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--text-faint)", whiteSpace: "nowrap", overflow: "hidden" }}>
              <span>{candidate.timestamp || "시간 없음"}</span>
              <span title="USN">USN {candidate.usn || "-"}</span>
              <span>부모 {candidate.parent_reference || "-"}</span>
              <span>@{candidate.record_offset || "-"}</span>
            </span>
          </>
        );
        const box: React.CSSProperties = { display: "grid", gap: 1, minWidth: 0, padding: "4px 8px", borderRadius: 6, border: `1px solid ${representative ? "var(--accent)" : "var(--border-subtle)"}`, background: "transparent", textAlign: "left", color: "inherit" };
        // Only records of this group can open here; others belong to another group.
        return member
          ? <button key={candidate.record_id} type="button" onClick={() => onSelect(member)} aria-label={`${candidate.file_name || "후보"} 기록 상세 보기`} style={{ ...box, cursor: "pointer" }}>{body}</button>
          : <div key={candidate.record_id} style={box}>{body}</div>;
      })}
    </div>
  );
  return (
    <section aria-label="이름 변경 근거" style={{ display: "grid", gap: 6, padding: "8px 10px", borderRadius: "var(--radius)", background: "var(--bg-elevated)", border: `1px solid ${paired ? "var(--border-subtle)" : "color-mix(in srgb, var(--warning) 45%, transparent)"}` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", fontSize: 11.5 }}>
        <strong style={{ fontSize: 11.5 }}>이름 변경</strong>
        <span style={{ fontWeight: 650, color: paired ? "var(--success)" : "var(--warning)" }}>{renameStatusLabel(event.status)}</span>
        {reasons.map((reason) => <span key={reason} style={{ color: "var(--text-dim)" }}>· {reason}</span>)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto minmax(0, 1fr)", gap: 10, alignItems: "start" }}>
        {column("이전 이름 (OLD)", sides.old)}
        <span aria-hidden="true" style={{ alignSelf: "center", color: "var(--text-faint)" }}>→</span>
        {column("새 이름 (NEW)", sides.new)}
      </div>
    </section>
  );
}
