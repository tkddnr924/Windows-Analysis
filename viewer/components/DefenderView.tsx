"use client";
// Microsoft Defender 활동 (docs-13) — _OVERVIEW Defender 전량(전량 로드 예외).
// 탐지 묶음·검사는 저장된 DefenderDetectionMembers/DefenderScans로 한 항목,
// 나머지는 레코드 1건 1항목. 요약 줄은 기간 내 저장 사건에서 센다(R02·R06).
import { useContext, useMemo, useState } from "react";
import BugReportOutlinedIcon from "@mui/icons-material/BugReportOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import DeleteSweepOutlinedIcon from "@mui/icons-material/DeleteSweepOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import ManageSearchOutlinedIcon from "@mui/icons-material/ManageSearchOutlined";
import MonitorHeartOutlinedIcon from "@mui/icons-material/MonitorHeartOutlined";
import PriorityHighOutlinedIcon from "@mui/icons-material/PriorityHighOutlined";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import TuneOutlinedIcon from "@mui/icons-material/TuneOutlined";
import UpdateOutlinedIcon from "@mui/icons-material/UpdateOutlined";
import WidgetsOutlinedIcon from "@mui/icons-material/WidgetsOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import { BookmarkButton, CardMain, CardName, CardShell, CountText, EventRow, IconTile, NoMatch, PagedEvents, Pill, PillRow, Sep, TimeCell, TimeSpan, isBookmarked, loadErrorNote, useCardState, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { CHANGE_LABELS, DEFAULT_DEFENDER_FILTER, EXCLUSION_LABELS, FEATURE_LABELS, RESULT_LABELS, buildDefenderItems, groupIndex, latestProtection, selectedSections, summarizeActivity, type DefenderFilter, type DefenderItem } from "@/lib/defenderActivity";
import { chronological } from "@/lib/eventOrder";
import { optionsOf, pageWindow, rowidOf, timeSpan } from "@/lib/eventCards";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "Defender";
const COMPANIONS = ["DefenderDetectionMembers", "DefenderScans", "DefenderResources", "DefenderProtectionStates"];
// Defender stores English result codes (success/failure/unknown).
const RESULT_COLOR: Record<string, string> = { success: "var(--success)", failure: "var(--danger)" };
const SEVERITY_COLOR: Record<string, string> = { 심각: "var(--danger)", 높음: "var(--danger)" };
const SCAN_OUTCOME: Record<string, { label: string; color: string }> = {
  start_and_completion: { label: "완료", color: "var(--success)" },
  completion_only: { label: "완료", color: "var(--success)" },
  start_and_cancel: { label: "중지", color: "var(--text-dim)" },
  cancel_only: { label: "중지", color: "var(--text-dim)" },
  start_and_error: { label: "오류 종료", color: "var(--danger)" },
  error_only: { label: "오류 종료", color: "var(--danger)" },
};
// Registry prefix shared by every Defender configuration target (raw on hover).
const CONFIG_PREFIX = /^HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\/i;

type Row = Record<string, string>;

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

function duration(seconds: string): string {
  const total = Number(seconds);
  if (!seconds || !Number.isFinite(total)) return "";
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return [h && `${h}시간`, m && `${m}분`, (s || (!h && !m)) && `${s}초`].filter(Boolean).join(" ");
}

const basename = (path: string) => path.split(/[\\/]/).pop() || path;
const targetText = (targets: string[]) => (targets.length > 1 ? `${targets[0]} 외 ${targets.length - 1}` : targets[0] ?? "");
const exclusionTitle = (row: Row) => `검사 제외 ${EXCLUSION_LABELS[row.config_exclusion_kind] ?? row.config_exclusion_kind} ${CHANGE_LABELS[row.config_change_kind] ?? ""}`.trim();
const configTarget = (row: Row) => (row.config_target || "").replace(CONFIG_PREFIX, "");

/** One-line stored-value summary per record kind; `targets` = stored resource values. */
function summaryOf(row: Row, targets: string[] = []): string {
  if (row.event_type === "configuration_changed") {
    if (row.config_exclusion_kind) return `${exclusionTitle(row)} · ${row.config_exclusion_value}`;
    const old = row.config_old_state === "value" ? row.config_old_value : "";
    const next = row.config_new_state === "value" ? row.config_new_value : "";
    return [configTarget(row), old || next ? `${old}${old && next ? " → " : ""}${next}` : ""].filter(Boolean).join(" · ");
  }
  if (row.section === "signature") {
    const signature = row.signature_version_previous && row.signature_version_current ? `${row.signature_version_previous} → ${row.signature_version_current}` : row.signature_version_current;
    const engine = row.engine_version_previous && row.engine_version_current && row.engine_version_previous !== row.engine_version_current ? `엔진 ${row.engine_version_previous} → ${row.engine_version_current}` : "";
    return [row.signature_type, row.update_type, signature || (row.event_type === "engine_updated" ? `${row.engine_version_previous} → ${row.engine_version_current}` : ""), engine, row.error_description].filter(Boolean).join(" · ");
  }
  if (row.section === "health") return [row.platform_version && `플랫폼 ${row.platform_version}`, row.av_signature_version && `정의 ${row.av_signature_version}`].filter(Boolean).join(" · ");
  if (row.section === "scan") return [row.scan_parameters, row.scan_type, duration(row.scan_duration_seconds)].filter(Boolean).join(" · ");
  if (row.section === "threat" || row.section === "threat_action") return [row.action && row.action !== "해당 없음" ? row.action : "", targetText(row.target_path ? [row.target_path] : targets)].filter(Boolean).join(" · ");
  if (row.section === "history") return "";
  return row.detail || row.description || "";
}

const ICONS: Record<string, React.ElementType> = { threat: BugReportOutlinedIcon, threat_action: BugReportOutlinedIcon, scan: ManageSearchOutlinedIcon, signature: UpdateOutlinedIcon, tampering: TuneOutlinedIcon, history: DeleteSweepOutlinedIcon, health: MonitorHeartOutlinedIcon, failure: PriorityHighOutlinedIcon };

function SummaryTile({ icon: Icon, label, value, title, wide, children }: { icon: React.ElementType; label: string; value?: React.ReactNode; title?: string; wide?: boolean; children?: React.ReactNode }) {
  return (
    <div title={title} style={{ gridColumn: wide ? "span 2" : undefined, display: "grid", alignContent: "start", gap: 6, minWidth: 0, padding: "10px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg)" }}>
      <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11.5, color: "var(--text-faint)" }}>
        <Icon sx={{ fontSize: 14 }} />{label}
      </span>
      {value !== undefined && <span style={{ fontSize: 18, fontWeight: 700, lineHeight: 1.1, color: "var(--text)", fontVariantNumeric: "tabular-nums" }}>{value}</span>}
      {children && <span style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap", fontSize: 11.5, color: "var(--text-dim)", minWidth: 0 }}>{children}</span>}
    </div>
  );
}

const unit = (count: number) => <>{count.toLocaleString()}<span style={{ fontSize: 12, fontWeight: 500, color: "var(--text-faint)", marginLeft: 2 }}>회</span></>;

export default function DefenderView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const scope = useContext(RecordScopeContext);
  const [filter, setFilter] = useState<DefenderFilter>(DEFAULT_DEFENDER_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange, sortDir]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<DefenderFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  // Stored groups and protection observations from the same _OVERVIEW file;
  // each table loads and fails on its own.
  const companion = useCompanionTables(scope?.fullPath, COMPANIONS);
  const { DefenderDetectionMembers: members, DefenderScans: scanTable, DefenderResources: resourceTable, DefenderProtectionStates: stateTable } = companion.tables;
  const index = useMemo(() => groupIndex(members?.rows ?? [], scanTable?.rows ?? []), [members, scanTable]);
  const scans = useMemo(() => new Map((scanTable?.rows ?? []).map((row) => [row.scan_entry_id, row])), [scanTable]);
  const resources = useMemo(() => {
    const byRecord = new Map<string, string[]>();
    for (const row of [...(resourceTable?.rows ?? [])].sort((a, b) => Number(a.ordinal) - Number(b.ordinal))) byRecord.set(row.record_id, [...(byRecord.get(row.record_id) ?? []), row.resource_value || row.resource_raw]);
    return byRecord;
  }, [resourceTable]);
  const states = useMemo(() => stateTable?.rows ?? [], [stateTable]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const items = useMemo(() => buildDefenderItems(data.rows, index, filter, inPeriod, rangeOn, sortDir), [data.rows, index, filter, inPeriod, rangeOn, sortDir]);
  const protection = useMemo(() => latestProtection(states, inPeriod), [states, inPeriod]);
  const summary = useMemo(() => summarizeActivity(data.rows, inPeriod, rangeOn), [data.rows, inPeriod, rangeOn]);
  const matchedEvents = items.reduce((sum, item) => sum + item.matched.size, 0);

  const accountOf = (row: Row) => row.account || (row.account_sid && resolveAccountDisplay(row.account_sid, accountDirectory)) || row.account_sid || "";
  const sectionOptions = useMemo(() => optionsOf(data.rows, (row) => row.section ?? "", (_value, row) => row.section_label || row.section), [data.rows]);
  const severityOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.severity), (row) => row.severity).map((option) => ({ ...option, color: SEVERITY_COLOR[option.value] })), [data.rows]);
  const categoryOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.category), (row) => row.category), [data.rows]);
  const resultOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.result), (row) => row.result, (value) => RESULT_LABELS[value] ?? value).map((option) => ({ ...option, color: RESULT_COLOR[option.value] })), [data.rows]);
  const sectionSelection = selectedSections(filter, sectionOptions.map((option) => option.value));

  const list = pageWindow(items.length, cardState.page);
  const periodNote = rangeOn ? "기간 내 " : "";

  const resultPill = (row: Row) => {
    const label = row.result && row.result !== "unknown" ? RESULT_LABELS[row.result] ?? row.result : "";
    return label ? <Pill color={RESULT_COLOR[row.result] ?? "var(--text-dim)"} title={row.result_basis || undefined}>{label}</Pill> : null;
  };

  /** Header line of a grouped item or single record. */
  const itemHead = (item: DefenderItem<Row>) => {
    // Representatives and range follow time, not the display direction.
    const ordered = chronological(item.events);
    const first = ordered[0];
    if (item.kind === "detection") {
      const detection = ordered.find((row) => row.section === "threat") ?? first;
      const action = [...ordered].reverse().find((row) => row.section === "threat_action");
      const paths = [...new Set(item.events.flatMap((row) => resources.get(row.record_id) ?? (row.target_path ? [row.target_path] : [])))];
      const tone = action?.result === "failure" ? "var(--danger)" : SEVERITY_COLOR[detection.severity] ?? "var(--text-dim)";
      return {
        icon: BugReportOutlinedIcon, tone,
        name: detection.threat_name || detection.title,
        tag: detection.category,
        line: [targetText(paths), detection.process && basename(detection.process), detection.detection_user].filter(Boolean).join(" · "),
        lineTitle: [...paths, detection.process, detection.detection_source && `탐지원 ${detection.detection_source}`].filter(Boolean).join("\n"),
        pills: <>
          {detection.severity && <Pill color={SEVERITY_COLOR[detection.severity] ?? "var(--text-dim)"}>{detection.severity}</Pill>}
          {action?.action && <Pill color={RESULT_COLOR[action.result] ?? "var(--text-dim)"} title={[action.remediation_user && `수행자 ${action.remediation_user}`, action.error_description].filter(Boolean).join("\n") || undefined}>{action.action}{action.result && action.result !== "unknown" ? ` ${RESULT_LABELS[action.result] ?? ""}` : ""}</Pill>}
        </>,
      };
    }
    if (item.kind === "scan") {
      const scan = scans.get(item.key);
      const outcome = scan ? SCAN_OUTCOME[scan.pairing_state] : undefined;
      const extra = [scan?.pause_count && scan.pause_count !== "0" && `일시중지 ${scan.pause_count}`, scan?.resume_count && scan.resume_count !== "0" && `재개 ${scan.resume_count}`];
      return {
        icon: ManageSearchOutlinedIcon, tone: outcome?.color === "var(--danger)" ? "var(--danger)" : "var(--text-dim)",
        name: scan?.scan_parameters || first.scan_parameters || "검사",
        tag: scan?.scan_type || first.scan_type,
        line: [duration(scan?.elapsed_seconds || scan?.reported_duration_seconds || ""), ...extra, scan?.user_raw].filter(Boolean).join(" · "),
        lineTitle: [scan?.scan_id, scan?.reported_duration_raw && `보고 소요 ${scan.reported_duration_raw}`].filter(Boolean).join("\n"),
        pills: outcome ? <Pill color={outcome.color}>{outcome.label}</Pill> : null,
      };
    }
    const exclusion = first.config_exclusion_kind;
    return {
      icon: ICONS[first.section] ?? WidgetsOutlinedIcon, tone: RESULT_COLOR[first.result] === "var(--danger)" ? "var(--danger)" : "var(--text-dim)",
      name: exclusion ? exclusionTitle(first) : first.title || first.description || first.event_type,
      tag: first.section_label,
      line: [exclusion ? first.config_exclusion_value : summaryOf(first, resources.get(first.record_id)), accountOf(first)].filter(Boolean).join(" · "),
      lineTitle: [first.config_target_raw, first.config_target && !exclusion ? first.config_target : "", first.history_cleared_time && `삭제 기준 ${first.history_cleared_time}`, first.description].filter(Boolean).join("\n"),
      pills: <>
        {first.config_change_kind && !exclusion && <Pill color="var(--text-dim)">{CHANGE_LABELS[first.config_change_kind] ?? first.config_change_kind}</Pill>}
        {resultPill(first)}
      </>,
    };
  };

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={ShieldOutlinedIcon} title="Microsoft Defender 활동" meta={`항목 ${items.length.toLocaleString()} · 일치 기록 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`} right={loadErrorNote(companion.failed)}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="위협 · 경로 · 프로세스 · 설정 · 계정 · SID" ariaLabel="Microsoft Defender 활동 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="구분" ariaLabel="구분" options={sectionOptions} selected={sectionSelection.length === sectionOptions.length ? [] : sectionSelection} onChange={(sections) => update({ sections })} />
        {severityOptions.length > 0 && <MultiSelectDropdown icon={<PriorityHighOutlinedIcon sx={{ fontSize: 15 }} />} label="심각도" ariaLabel="심각도" options={severityOptions} selected={filter.severities} onChange={(severities) => update({ severities })} />}
        {categoryOptions.length > 0 && <MultiSelectDropdown icon={<BugReportOutlinedIcon sx={{ fontSize: 15 }} />} label="분류" ariaLabel="분류" options={categoryOptions} selected={filter.categories} onChange={(categories) => update({ categories })} />}
        {resultOptions.length > 0 && <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={resultOptions} selected={filter.results} onChange={(results) => update({ results })} />}
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <div role="region" aria-label="활동 요약" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(170px, 1fr))", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {protection.length > 0 && (
          <SummaryTile icon={ShieldOutlinedIcon} label={`${periodNote}마지막 보호 상태`} wide>
            <span style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "4px 14px", width: "100%" }}>
              {protection.map((entry) => {
                const color = entry.state === "off" ? "var(--danger)" : entry.state === "on" ? "var(--success)" : "var(--text-faint)";
                return (
                  <span key={entry.feature} title={entry.state ? `${periodNote}마지막 관측 ${entry.time}\n관측 ${entry.count.toLocaleString()}회 (${entry.first} → ${entry.time})` : `${entry.time} 같은 시각 관측 ${entry.tie}건의 상태가 서로 다름`} style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, fontSize: 12.5 }}>
                    <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%", flexShrink: 0, background: color }} />
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)" }}>{FEATURE_LABELS[entry.feature] ?? entry.feature}</span>
                    <span style={{ flexShrink: 0, fontWeight: 700, color: entry.state === "off" ? "var(--danger)" : "var(--text)" }}>{entry.state === "on" ? "켜짐" : entry.state === "off" ? "꺼짐" : "확정 불가"}</span>
                  </span>
                );
              })}
            </span>
          </SummaryTile>
        )}
        {summary.scan.started + summary.scan.completed + summary.scan.cancelled + summary.scan.failed > 0 && (
          <SummaryTile icon={ManageSearchOutlinedIcon} label="검사" value={unit(summary.scan.started)} title={summary.scan.last && `최근 ${summary.scan.last}`}>
            <span>완료 {summary.scan.completed}</span>
            {summary.scan.cancelled > 0 && <span>중지 {summary.scan.cancelled}</span>}
            {summary.scan.failed > 0 && <span style={{ color: "var(--danger)", fontWeight: 700 }}>오류 {summary.scan.failed}</span>}
          </SummaryTile>
        )}
        {summary.signature.updated + summary.signature.failed > 0 && (
          <SummaryTile icon={UpdateOutlinedIcon} label="정의 업데이트" value={unit(summary.signature.updated)} title={summary.signature.last && `최근 ${summary.signature.last}`}>
            {summary.signature.version && <span style={{ fontFamily: "var(--mono)" }}>{summary.signature.version}</span>}
            {summary.signature.failed > 0 && <span style={{ color: "var(--danger)", fontWeight: 700 }}>실패 {summary.signature.failed}</span>}
          </SummaryTile>
        )}
        {summary.config.count > 0 && (
          <SummaryTile icon={TuneOutlinedIcon} label="보호 설정 변경" value={unit(summary.config.count)} title={summary.config.last && `최근 ${summary.config.last}`}>
            {summary.config.exclusionsAdded > 0 && <span style={{ color: "var(--text)", fontWeight: 700 }}>검사 제외 추가 {summary.config.exclusionsAdded}</span>}
            {summary.config.exclusionsRemoved > 0 && <span style={{ color: "var(--text)", fontWeight: 700 }}>검사 제외 삭제 {summary.config.exclusionsRemoved}</span>}
          </SummaryTile>
        )}
        {summary.history.count > 0 && (
          <SummaryTile icon={DeleteSweepOutlinedIcon} label="기록 삭제" value={unit(summary.history.count)} title={summary.history.last && `최근 ${summary.history.last}`}>
            <span style={{ fontFamily: "var(--mono)", color: "var(--text-time)" }}>{summary.history.last.slice(0, 16)}</span>
          </SummaryTile>
        )}
      </div>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {items.length === 0 && <NoMatch total={data.rows.length} />}
        {items.slice(list.start, list.end).map((item) => {
          const head = itemHead(item);
          const grouped = item.kind !== "record";
          const single = item.events[0];
          const span = timeSpan(item.events);
          return (
            <CardShell key={item.key} label={head.name} tone={head.tone} mark={<IconTile icon={head.icon} tone={head.tone} />}
              expandable={grouped} open={grouped && cardState.isOpen(item.key)} onActivate={() => (grouped ? cardState.toggle(item.key) : setSelected(single))} buttonLabel={grouped ? undefined : `${head.name} 상세 보기`}
              bookmarked={!grouped && isBookmarked(single, bookmarks)} side={!grouped && <BookmarkButton row={single} bookmarks={bookmarks} />} regionLabel="기록"
              body={<PagedEvents events={item.events} page={cardState.eventPage(item.key)} onPage={(next) => cardState.setEventPage(item.key, next)} label={`${head.name} 기록 페이지`}
                render={(row, index) => {
                  const targets = resources.get(row.record_id) ?? [];
                  const text = summaryOf(row, targets);
                  return (
                    <EventRow key={row.record_id} row={row} index={index} matched={item.matched.has(row.record_id)} bookmarks={bookmarks} onOpen={() => setSelected(row)} openLabel={`${row.timestamp} ${row.title || row.event_type} 상세 보기`}>
                      <TimeCell value={row.timestamp} />
                      <span style={{ width: 120, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{row.title || row.event_type}</span>
                      {resultPill(row)}
                      <span title={[...targets, row.remediation_user && `수행자 ${row.remediation_user}`].filter(Boolean).join("\n") || text || undefined} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{text}</span>
                      <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
                    </EventRow>
                  );
                }} />}>
              <CardMain
                title={<>
                  <CardName>{head.name}</CardName>
                  {head.tag && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5 }}>{head.tag}</span>}
                </>}
                sub={(head.line || grouped) && <>
                  {head.line && <span title={head.lineTitle || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{head.line}</span>}
                  {grouped && <>
                    {head.line && <Sep />}
                    <CountText unit="기록" matched={item.matched.size} total={item.events.length} />
                  </>}
                </>} />
              <PillRow>{head.pills}</PillRow>
              <TimeSpan from={span.from} to={span.to} />
            </CardShell>
          );
        })}
        {items.length > 0 && <PaginationControls ariaLabel="Defender 항목 페이지" page={list.page} pageCount={list.pageCount} onChange={cardState.setPage} summary={list.summary} />}
      </main>

      {selected && (
        <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
          onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(rowidOf(selected)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowidOf(selected)) : undefined} />
      )}
    </div>
  );
}
