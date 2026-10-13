"use client";
// 휴지통 — _OVERVIEW RecycleBin 전량. $I 한 건이 카드 하나(수집된 $I 파일 또는 MFT 상주 $I).
import { useMemo, useState } from "react";
import DeleteOutlineOutlinedIcon from "@mui/icons-material/DeleteOutlineOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import { BookmarkButton, CardMain, CardName, CardShell, IconTile, NoMatch, Pill, PillRow, TimeSpan, isBookmarked, useCardState, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { DEFAULT_RECYCLE_FILTER, filterRecycleRows, recycleFileName, type RecycleFilter } from "@/lib/recycleBin";
import { formatSize } from "@/lib/byteSize";
import { optionsOf, pageWindow, rowidOf } from "@/lib/eventCards";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "RecycleBin";
const TONE = "var(--text-dim)";

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

export default function RecycleBinView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<RecycleFilter>(DEFAULT_RECYCLE_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange, sortDir]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<RecycleFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const rows = useMemo(() => filterRecycleRows(data.rows, filter, inPeriod, rangeActive(timeRange), sortDir), [data.rows, filter, inPeriod, timeRange, sortDir]);
  const accountLabel = (row: Row) => row.account || (row.account_sid && resolveAccountDisplay(row.account_sid, accountDirectory)) || row.account_sid || "";
  const accountOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.account_sid), (row) => row.account_sid, (_value, row) => accountLabel(row)), [data.rows, accountDirectory]);

  const list = pageWindow(rows.length, cardState.page);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={DeleteOutlineOutlinedIcon} title="휴지통" meta={`항목 ${rows.length.toLocaleString()} / ${data.rows.length.toLocaleString()}`}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="파일 · 원래 경로 · 계정 · SID" ariaLabel="휴지통 검색" width={280} />
        {accountOptions.length > 0 && <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />}
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {rows.length === 0 && <NoMatch total={data.rows.length} />}
        {rows.slice(list.start, list.end).map((row) => {
          const failed = Boolean(row.status) && row.status !== "ok";
          const tone = failed ? "var(--danger)" : TONE;
          const name = recycleFileName(row) || row.mft_path || row.record_id;
          const account = accountLabel(row);
          const size = row.file_size ? formatSize(row.file_size) : "";
          return (
            <CardShell key={row.record_id} label={name} tone={tone} mark={<IconTile icon={DeleteOutlineOutlinedIcon} tone={tone} />}
              expandable={false} open={false} onActivate={() => setSelected(row)} buttonLabel={`${name} 상세 보기`}
              bookmarked={isBookmarked(row, bookmarks)} side={<BookmarkButton row={row} bookmarks={bookmarks} />} regionLabel="휴지통 기록">
              <CardMain
                title={<>
                  <CardName>{name}</CardName>
                  {account && <span title={row.account_sid || undefined} style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5 }}>{account}</span>}
                </>}
                sub={(row.original_path || failed) && (
                  <span title={[row.original_path, row.mft_path, row.error].filter(Boolean).join("\n") || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", color: failed ? "var(--danger)" : undefined }}>
                    {row.original_path || row.error}
                  </span>
                )} />
              <PillRow>
                {size && <span title={`${Number(row.file_size).toLocaleString()} Bytes`} style={{ flexShrink: 0, color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12, marginRight: 4 }}>{size}</span>}
                {row.r_exists === "1" && <Pill>$R 있음</Pill>}
                {row.r_exists === "0" && <Pill color="var(--text-faint)">$R 없음</Pill>}
                {row.mft_path && <Pill color="var(--text-faint)" title={[row.mft_path, row.mft_entry && `MFT 엔트리 ${row.mft_entry}${row.mft_seq ? ` / 시퀀스 ${row.mft_seq}` : ""}`].filter(Boolean).join("\n")}>MFT</Pill>}
                {failed && <Pill color="var(--danger)" title={row.error || undefined}>파싱 실패</Pill>}
              </PillRow>
              <TimeSpan from={row.timestamp ?? ""} to={row.timestamp ?? ""} />
            </CardShell>
          );
        })}
        {rows.length > 0 && <PaginationControls ariaLabel="휴지통 페이지" page={list.page} pageCount={list.pageCount} onChange={cardState.setPage} summary={list.summary} />}
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
