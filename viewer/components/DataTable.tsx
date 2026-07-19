"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnFiltersState,
  type Row,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { ColumnFilterValue, CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import RowDetailPanel from "./RowDetailPanel";
import ColumnFilterControl from "./ColumnFilterControl";

const ROW_HEIGHT = 26;
const DEFAULT_COLUMN_WIDTH = 220;
const MIN_COLUMN_WIDTH = 60;
const DETAIL_COLUMN_ID = "__detail";
const DETAIL_COLUMN_WIDTH = 50;

function columnFilterFn(row: Row<Record<string, string>>, columnId: string, filterValue: ColumnFilterValue) {
  if (!filterValue?.value) return true;
  const cellValue = String(row.getValue(columnId) ?? "").toLowerCase();
  const needle = filterValue.value.toLowerCase();
  if (filterValue.mode === "exclude") return !cellValue.includes(needle);
  if (filterValue.mode === "exact") return cellValue === needle;
  return cellValue.includes(needle);
}

// The CSV on disk always leads with time (right for the data file), but a
// table where several timestamp columns bury the "what happened" field
// off-screen defeats scanning at a glance — pull an artifact's declared
// priority columns to the front for display; everything else keeps its
// original relative order after them.
function orderColumns(allColumns: string[], priority: string[] | undefined): string[] {
  if (!priority || priority.length === 0) return allColumns;
  const prioritySet = new Set(priority);
  const ordered = priority.filter((c) => allColumns.includes(c));
  const rest = allColumns.filter((c) => !prioritySet.has(c));
  return [...ordered, ...rest];
}

interface DataTableProps {
  fileName: string;
  data: CsvData;
  initialFilter?: { column: string; value: string } | null;
  onInitialFilterConsumed?: () => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** rowids (this file's __rowid) currently bookmarked — undefined/omitted hides the star entirely. */
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
}

export default function DataTable({
  fileName,
  data,
  initialFilter,
  onInitialFilterConsumed,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
}: DataTableProps) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [search, setSearch] = useState("");
  const [selectedCell, setSelectedCell] = useState<{ row: Record<string, string>; column: string } | null>(null);

  const fileBaseName = fileName.split(/[\\/]/).pop()?.replace(/\.csv$/i, "") ?? fileName;
  const artifactSpec = getArtifactView(fileBaseName);

  useEffect(() => {
    if (!initialFilter) return;
    setColumnFilters([{ id: initialFilter.column, value: { mode: "exact", value: initialFilter.value } }]);
    onInitialFilterConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialFilter]);

  const displayColumns = useMemo(
    () => orderColumns(data.columns, artifactSpec?.priorityColumns),
    [data.columns, artifactSpec]
  );

  const columnHelper = createColumnHelper<Record<string, string>>();
  const columns = useMemo(
    () => [
      // Not rendered (hidden via columnVisibility below) — exists purely so
      // Master Timeline / Bookmark "jump to source row" links can filter
      // down to one exact row via setColumnFilters, the same mechanism
      // regular cross-artifact links already use.
      columnHelper.accessor((row) => String((row as unknown as Record<string, unknown>).__rowid ?? ""), {
        id: "__rowid",
        header: "",
        cell: () => null,
        filterFn: columnFilterFn,
      }),
      columnHelper.display({
        id: DETAIL_COLUMN_ID,
        header: "",
        size: DETAIL_COLUMN_WIDTH,
        enableResizing: false,
        cell: ({ row }) => {
          const tags = artifactSpec?.tags?.(row.original) ?? [];
          const rowid = Number((row.original as Record<string, unknown>).__rowid);
          const bookmarked = bookmarkedRowids?.has(rowid) ?? false;
          return (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 3 }}>
              {onToggleBookmark && Number.isFinite(rowid) && (
                <span
                  onClick={(e) => {
                    e.stopPropagation();
                    onToggleBookmark(rowid);
                  }}
                  title={bookmarked ? "북마크 해제" : "북마크에 추가"}
                  style={{ cursor: "pointer", color: bookmarked ? "var(--warning)" : "var(--text-faint)" }}
                >
                  {bookmarked ? "★" : "☆"}
                </span>
              )}
              {tags.length > 0 && (
                <span
                  title={tags.map((t) => (t.description ? `${t.label} — ${t.description}` : t.label)).join("\n\n")}
                  style={{ color: tags.some((t) => t.severity === "danger") ? "var(--danger)" : "var(--warning)" }}
                >
                  {tags.some((t) => t.severity === "danger") ? "⛔" : "⚠"}
                </span>
              )}
            </span>
          );
        },
      }),
      ...(artifactSpec?.computedColumns ?? []).map((c) =>
        columnHelper.accessor((row) => c.compute(row) ?? "", {
          id: c.key,
          header: c.label,
          cell: (info) => info.getValue(),
          filterFn: columnFilterFn,
          size: c.size ?? 200,
          minSize: MIN_COLUMN_WIDTH,
        })
      ),
      ...displayColumns.map((col) =>
        columnHelper.accessor(col, {
          header: col,
          cell: (info) => info.getValue(),
          filterFn: columnFilterFn,
          size: DEFAULT_COLUMN_WIDTH,
          minSize: MIN_COLUMN_WIDTH,
        })
      ),
    ],
    [displayColumns, artifactSpec, bookmarkedRowids, onToggleBookmark] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const searchedRows = useMemo(() => {
    if (!search.trim()) return data.rows;
    const needle = search.toLowerCase();
    return data.rows.filter((row) => data.columns.some((col) => (row[col] ?? "").toLowerCase().includes(needle)));
  }, [data.rows, data.columns, search]);

  const table = useReactTable({
    data: searchedRows,
    columns,
    state: { sorting, columnFilters, columnVisibility: { __rowid: false } },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    columnResizeMode: "onChange",
    enableColumnResizing: true,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const { rows } = table.getRowModel();

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const virtualRows = virtualizer.getVirtualItems();
  const totalHeight = virtualizer.getTotalSize();
  const paddingTop = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom = virtualRows.length > 0 ? totalHeight - virtualRows[virtualRows.length - 1].end : 0;

  const activeFilterCount = columnFilters.length;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minWidth: 0 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "9px 14px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-panel)",
          flexShrink: 0,
        }}
      >
        <strong style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13 }}>{fileName}</strong>
        <span style={{ color: "var(--text-faint)", flexShrink: 0, fontSize: 11.5 }}>
          {rows.length.toLocaleString()} / {data.rowCount.toLocaleString()} rows · {data.columns.length} cols
        </span>
        {activeFilterCount > 0 && (
          <button
            onClick={() => setColumnFilters([])}
            style={{
              flexShrink: 0,
              fontSize: 11,
              padding: "3px 9px",
              background: "var(--accent-subtle)",
              color: "var(--accent)",
              border: "1px solid var(--accent)",
              borderRadius: "var(--radius-lg)",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            필터 {activeFilterCount}개 초기화 ×
          </button>
        )}
        <div style={{ position: "relative", marginLeft: "auto", width: 260 }}>
          <span style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", fontSize: 12, color: "var(--text-faint)", pointerEvents: "none" }}>
            🔍
          </span>
          <input
            placeholder="전체 검색..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: "100%",
              padding: "6px 8px 6px 28px",
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              color: "var(--text)",
            }}
          />
        </div>
      </div>

      <div ref={scrollRef} style={{ flex: 1, overflow: "auto", position: "relative" }}>
        <table style={{ borderCollapse: "collapse", tableLayout: "fixed", fontFamily: "var(--mono)", width: table.getTotalSize() }}>
          <thead style={{ position: "sticky", top: 0, zIndex: 1, background: "var(--bg-panel)" }}>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  const isDetailColumn = header.column.id === DETAIL_COLUMN_ID;
                  const sortDir = header.column.getIsSorted();
                  return (
                    <th
                      key={header.id}
                      style={{
                        position: "relative",
                        width: header.getSize(),
                        textAlign: "left",
                        padding: "7px 8px",
                        borderBottom: "1px solid var(--border)",
                        borderRight: "1px solid var(--border-subtle)",
                        userSelect: "none",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        fontSize: 12,
                        fontWeight: 600,
                        color: "var(--text-dim)",
                      }}
                      title={isDetailColumn ? "" : header.column.id}
                    >
                      {isDetailColumn ? null : (
                        <>
                          <span
                            onClick={header.column.getToggleSortingHandler()}
                            style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5, color: sortDir ? "var(--text)" : undefined }}
                            title="클릭하여 정렬"
                          >
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            <span
                              style={{
                                fontSize: 9,
                                lineHeight: 1,
                                color: sortDir ? "var(--accent)" : "var(--text-faint)",
                                opacity: sortDir ? 1 : 0.6,
                              }}
                            >
                              {sortDir === "asc" ? "▲" : sortDir === "desc" ? "▼" : "⇅"}
                            </span>
                          </span>
                          <div
                            onMouseDown={header.getResizeHandler()}
                            onTouchStart={header.getResizeHandler()}
                            style={{
                              position: "absolute",
                              right: 0,
                              top: 0,
                              height: "100%",
                              width: 6,
                              cursor: "col-resize",
                              background: header.column.getIsResizing() ? "var(--accent)" : "transparent",
                            }}
                          />
                        </>
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={`${headerGroup.id}-filters`}>
                {headerGroup.headers.map((header) => (
                  <th
                    key={`${header.id}-filter`}
                    style={{
                      width: header.getSize(),
                      padding: "4px 5px",
                      borderBottom: "1px solid var(--border)",
                      borderRight: "1px solid var(--border-subtle)",
                      background: "var(--bg-panel)",
                      fontWeight: 400,
                    }}
                  >
                    {header.column.id !== DETAIL_COLUMN_ID && (
                      <ColumnFilterControl
                        value={header.column.getFilterValue() as ColumnFilterValue | undefined}
                        onChange={(v) => header.column.setFilterValue(v)}
                      />
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {paddingTop > 0 && (
              <tr>
                <td style={{ height: paddingTop, padding: 0, border: "none" }} />
              </tr>
            )}
            {virtualRows.map((virtualRow) => {
              const row = rows[virtualRow.index];
              return (
                <tr
                  key={row.id}
                  style={{
                    height: ROW_HEIGHT,
                    background: virtualRow.index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = virtualRow.index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)")}
                >
                  {row.getVisibleCells().map((cell) => {
                    const isDetailColumn = cell.column.id === DETAIL_COLUMN_ID;
                    return (
                      <td
                        key={cell.id}
                        onClick={
                          isDetailColumn
                            ? undefined
                            : () => setSelectedCell({ row: row.original, column: cell.column.id })
                        }
                        style={{
                          width: cell.column.getSize(),
                          padding: isDetailColumn ? "0 6px" : "0 8px",
                          borderRight: "1px solid var(--border-subtle)",
                          whiteSpace: "nowrap",
                          overflow: isDetailColumn ? "visible" : "hidden",
                          textOverflow: isDetailColumn ? "clip" : "ellipsis",
                          cursor: isDetailColumn ? "default" : "pointer",
                          fontSize: 12.5,
                        }}
                        title={isDetailColumn ? "" : String(cell.getValue() ?? "")}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
            {paddingBottom > 0 && (
              <tr>
                <td style={{ height: paddingBottom, padding: 0, border: "none" }} />
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selectedCell && (() => {
        const selRowid = Number((selectedCell.row as Record<string, unknown>).__rowid);
        const canBookmark = onToggleBookmark && Number.isFinite(selRowid);
        return (
          <RowDetailPanel
            row={selectedCell.row}
            columns={displayColumns}
            focusedColumn={selectedCell.column}
            fileBaseName={fileBaseName}
            onClose={() => setSelectedCell(null)}
            onNavigate={(targetFile, targetColumn, value) => {
              setSelectedCell(null);
              onNavigate(targetFile, targetColumn, value);
            }}
            onFetchLinkedRows={onFetchLinkedRows}
            isBookmarked={canBookmark ? bookmarkedRowids?.has(selRowid) ?? false : undefined}
            onToggleBookmark={canBookmark ? () => onToggleBookmark!(selRowid) : undefined}
          />
        );
      })()}
    </div>
  );
}
