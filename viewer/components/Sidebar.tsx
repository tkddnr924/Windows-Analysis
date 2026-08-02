"use client";

import { useEffect, useMemo, useState } from "react";
import type { CaseSummary, CategoryEntry, ResultFileEntry } from "@/lib/types";
import { groupKeyFor } from "@/lib/fileGrouping";
import { getArtifactView } from "@/lib/artifactViews";
import { EMPTY_TIME_RANGE, rangeActive, type TimeRange } from "@/lib/timeRange";
import DateTimeInput from "./DateTimeInput";

const timeInputStyle: React.CSSProperties = {
  width: "100%",
  padding: "5px 8px",
  background: "var(--bg-input)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  color: "var(--text)",
  fontSize: 11.5,
  fontFamily: "var(--mono)",
  colorScheme: "dark",
};

export const CATEGORY_ICONS: Record<string, string> = {
  AMCACHE: "📦",
  BROWSER: "🌐",
  EVENTLOG: "📋",
  JUMPLIST: "🔗",
  PREFETCH: "⚡",
  REGISTRY: "🗂️",
  SRUM: "📊",
  WER: "💥",
  TASKSCHEDULER: "⏰",
  POWERSHELL: "💻",
  FILESYSTEM: "🗄️",
};

// Maps a run-list artifact name to its output CATEGORY folder (upper-cased),
// so the sidebar can show every artifact that ran — including ones that found
// no source files (no folder on disk) — as a "데이터 없음" placeholder.
// Category defaults to the artifact name; only UsnJrnl files under FileSystem.
const ARTIFACT_CATEGORY: Record<string, string> = {
  UsnJrnl: "FILESYSTEM",
};

function categoryForArtifact(name: string): string {
  return ARTIFACT_CATEGORY[name] ?? name.toUpperCase();
}

function EmptyCategoryRow({ name }: { name: string }) {
  return (
    <div
      title="이 아티팩트는 실행됐지만 대상에서 원본 파일을 찾지 못했습니다"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        padding: "8px 10px",
        fontSize: 12.5,
        fontWeight: 600,
        color: "var(--text-faint)",
        opacity: 0.5,
        userSelect: "none",
        cursor: "default",
      }}
    >
      <span style={{ width: 10, display: "inline-block" }} />
      {CATEGORY_ICONS[name] && <span>{CATEGORY_ICONS[name]}</span>}
      <span>{name}</span>
      <span style={{ marginLeft: "auto", fontSize: 10.5, fontWeight: 400 }}>데이터 없음</span>
    </div>
  );
}

const OVERVIEW_TABLE_ICONS: Record<string, string> = {
  TargetInfo: "🖥️",
  ExecutionHistory: "⚡",
  RemoteDesktopHistory: "🖥️",
  BrowserTimeline: "🌐",
};

interface FileRowProps {
  file: ResultFileEntry;
  selected: boolean;
  indent: number;
  icon?: string;
  onSelectFile: (file: ResultFileEntry) => void;
}

function FileRow({ file, selected, indent, icon, onSelectFile }: FileRowProps) {
  return (
    <div
      onClick={() => onSelectFile(file)}
      title={file.relativePath}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 6,
        padding: `5px 10px 5px ${indent}px`,
        cursor: "pointer",
        background: selected ? "var(--bg-selected)" : "transparent",
        borderLeft: `2px solid ${selected ? "var(--accent)" : "transparent"}`,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}
      onMouseEnter={(e) => {
        if (!selected) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected) e.currentTarget.style.background = "transparent";
      }}
    >
      <span style={{ display: "flex", alignItems: "center", gap: 5, overflow: "hidden", textOverflow: "ellipsis", color: selected ? "var(--text)" : "var(--text-dim)" }}>
        {icon && <span style={{ flexShrink: 0, fontSize: 12 }}>{icon}</span>}
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{file.name}</span>
      </span>
      <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{file.rowCount.toLocaleString()}</span>
    </div>
  );
}

interface GroupedFileRowsProps {
  file: ResultFileEntry;
  groupColumn: string;
  label: (value: string) => string;
  indent: number;
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
}

// Renders a groupable table (e.g. EventLog_Events) not as a single row but as
// its per-value entries directly under the category — one row per distinct
// value of groupColumn (Security.evtx, Application.evtx, ...), preceded by a
// "전체" row that opens the merged table. Clicking a value row opens the table
// filtered to it. The values load lazily once the category is expanded.
function GroupedFileRows({ file, groupColumn, label, indent, selectedFile, onSelectFile, onNavigate }: GroupedFileRowsProps) {
  const [values, setValues] = useState<{ value: string; count: number }[] | null>(null);

  useEffect(() => {
    let alive = true;
    window.api.listColumnValues(file.fullPath, groupColumn).then((v) => {
      if (alive) setValues(v);
    });
    return () => {
      alive = false;
    };
  }, [file.fullPath, groupColumn]);

  const selected = selectedFile?.fullPath === file.fullPath;

  return (
    <div>
      <div
        onClick={() => onSelectFile(file)}
        title="모든 로그 통합"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 6,
          padding: `5px 10px 5px ${indent}px`,
          cursor: "pointer",
          background: selected ? "var(--bg-selected)" : "transparent",
          borderLeft: `2px solid ${selected ? "var(--accent)" : "transparent"}`,
          whiteSpace: "nowrap",
          overflow: "hidden",
        }}
        onMouseEnter={(e) => {
          if (!selected) e.currentTarget.style.background = "var(--bg-hover)";
        }}
        onMouseLeave={(e) => {
          if (!selected) e.currentTarget.style.background = "transparent";
        }}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 5, overflow: "hidden", textOverflow: "ellipsis", color: selected ? "var(--text)" : "var(--text-dim)" }}>
          <span style={{ flexShrink: 0, fontSize: 12 }}>📚</span>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>전체</span>
        </span>
        <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{file.rowCount.toLocaleString()}</span>
      </div>
      {values === null && (
        <div style={{ padding: `4px 10px 4px ${indent + 6}px`, fontSize: 11.5, color: "var(--text-faint)" }}>불러오는 중...</div>
      )}
      {values?.map((v) => (
        <div
          key={v.value}
          onClick={() => onNavigate(file.name, groupColumn, v.value)}
          title={label(v.value)}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 8,
            padding: `4px 10px 4px ${indent + 6}px`,
            cursor: "pointer",
            color: "var(--text-dim)",
            fontSize: 12,
            whiteSpace: "nowrap",
            overflow: "hidden",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{label(v.value) || "(빈 값)"}</span>
          <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{v.count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

interface GroupNodeProps {
  groupName: string;
  files: ResultFileEntry[];
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
}

function GroupNode({ groupName, files, selectedFile, onSelectFile }: GroupNodeProps) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div>
      <div
        onClick={() => setExpanded((e) => !e)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "5px 10px 5px 24px",
          cursor: "pointer",
          userSelect: "none",
          color: "var(--text-dim)",
          fontSize: 12.5,
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text)")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-dim)")}
      >
        <span style={{ width: 10, display: "inline-block", fontSize: 9, color: "var(--text-faint)" }}>{expanded ? "▾" : "▸"}</span>
        <span>{groupName}</span>
        <span style={{ color: "var(--text-faint)" }}>{files.length}</span>
      </div>
      {expanded &&
        files.map((file) => (
          <FileRow
            key={file.fullPath}
            file={file}
            selected={selectedFile?.fullPath === file.fullPath}
            indent={44}
            onSelectFile={onSelectFile}
          />
        ))}
    </div>
  );
}

interface CategoryNodeProps {
  category: CategoryEntry;
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
  /** Friendly label to show instead of the raw folder name (e.g. "_OVERVIEW" -> "종합 분석"). */
  displayName?: string;
  /** Pinned sections (the curated cross-artifact overview) are always
   * expanded and visually distinguished from the raw per-artifact tree. */
  pinned?: boolean;
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
}

function CategoryNode({ category, selectedFile, onSelectFile, displayName, pinned, onNavigate }: CategoryNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const [files, setFiles] = useState<ResultFileEntry[] | null>(null);

  useEffect(() => {
    window.api.listResultFiles(category.fullPath).then(setFiles);
  }, [category.fullPath]);

  const groups = useMemo(() => {
    if (!files) return null;
    const map = new Map<string, ResultFileEntry[]>();
    for (const file of files) {
      const key = groupKeyFor(file.relativePath);
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(file);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [files]);

  // A second tree level is only worth it when it actually splits the
  // list into more than one group — otherwise it's just an extra click.
  // The pinned overview section is a small, fixed set of primary nav
  // items (TargetInfo/ExecutionHistory/...) — always shown flat, never
  // folded into single-item groups.
  const shouldGroup = !pinned && (groups?.length ?? 0) > 1;
  const isExpanded = pinned || expanded;
  const icon = pinned ? undefined : CATEGORY_ICONS[category.name];

  return (
    <div
      style={
        pinned
          ? { background: "linear-gradient(180deg, rgba(88,166,255,0.07), rgba(88,166,255,0.02))", borderBottom: "1px solid var(--border-subtle)" }
          : undefined
      }
    >
      <div
        onClick={() => !pinned && setExpanded((e) => !e)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "8px 10px",
          cursor: pinned ? "default" : "pointer",
          fontWeight: 600,
          fontSize: 12.5,
          userSelect: "none",
          color: pinned ? "var(--accent)" : "var(--text)",
        }}
      >
        {!pinned && (
          <span style={{ width: 10, display: "inline-block", fontSize: 9, color: "var(--text-faint)" }}>{expanded ? "▾" : "▸"}</span>
        )}
        {icon && <span>{icon}</span>}
        {pinned && <span style={{ fontSize: 12 }}>✦</span>}
        <span>{displayName ?? category.name}</span>
        <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{files ? files.length : ""}</span>
      </div>
      {isExpanded && files && (
        <div style={{ paddingBottom: pinned ? 4 : 0 }}>
          {files.length === 0 && (
            <div style={{ padding: "4px 10px 8px 28px", color: "var(--text-faint)", fontSize: 12 }}>결과 없음</div>
          )}
          {shouldGroup
            ? groups!.map(([groupName, groupFiles]) => (
                <GroupNode
                  key={groupName}
                  groupName={groupName}
                  files={groupFiles}
                  selectedFile={selectedFile}
                  onSelectFile={onSelectFile}
                />
              ))
            : files.map((file) => {
                const spec = getArtifactView(file.name);
                // A groupable table (e.g. EventLog_Events) is shown split into
                // its per-value entries directly under the category, rather than
                // as one row.
                if (spec?.sidebarGroupColumn && onNavigate) {
                  return (
                    <GroupedFileRows
                      key={file.fullPath}
                      file={file}
                      groupColumn={spec.sidebarGroupColumn}
                      label={spec.sidebarGroupLabel ?? ((v) => v)}
                      indent={pinned ? 20 : 26}
                      selectedFile={selectedFile}
                      onSelectFile={onSelectFile}
                      onNavigate={onNavigate}
                    />
                  );
                }
                return (
                  <FileRow
                    key={file.fullPath}
                    file={file}
                    selected={selectedFile?.fullPath === file.fullPath}
                    indent={pinned ? 20 : 26}
                    icon={pinned ? OVERVIEW_TABLE_ICONS[file.name] : undefined}
                    onSelectFile={onSelectFile}
                  />
                );
              })}
        </div>
      )}
    </div>
  );
}

interface PinnedNavRowProps {
  icon: string;
  label: string;
  count?: number;
  selected: boolean;
  onClick: () => void;
}

function PinnedNavRow({ icon, label, count, selected, onClick }: PinnedNavRowProps) {
  return (
    <div
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "9px 12px",
        cursor: "pointer",
        fontSize: 12.5,
        fontWeight: 600,
        background: selected ? "var(--bg-selected)" : "transparent",
        borderLeft: `2px solid ${selected ? "var(--accent)" : "transparent"}`,
        color: selected ? "var(--text)" : "var(--text-dim)",
      }}
      onMouseEnter={(e) => {
        if (!selected) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected) e.currentTarget.style.background = "transparent";
      }}
    >
      <span>{icon}</span>
      <span>{label}</span>
      {count !== undefined && <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{count}</span>}
    </div>
  );
}

interface SidebarProps {
  cases: CaseSummary[];
  casesError: string | null;
  selectedCase: CaseSummary | null;
  onSelectCase: (c: CaseSummary) => void;
  categories: CategoryEntry[];
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
  activeVirtualTab: "timeline" | "bookmarks" | null;
  onSelectTimeline: () => void;
  onSelectBookmarks: () => void;
  bookmarkCount: number;
  timeRange: TimeRange;
  onTimeRangeChange: (range: TimeRange) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
}

export default function Sidebar({
  cases,
  casesError,
  selectedCase,
  onSelectCase,
  categories,
  selectedFile,
  onSelectFile,
  activeVirtualTab,
  onSelectTimeline,
  onSelectBookmarks,
  bookmarkCount,
  timeRange,
  onTimeRangeChange,
  onNavigate,
}: SidebarProps) {
  const overviewCategory = categories.find((c) => c.name === "_OVERVIEW");
  const rawCategories = categories.filter((c) => c.name !== "_OVERVIEW");

  // Every artifact that ran, mapped to its category, in run order — so the
  // "원본 데이터" list is 1:1 with the run list. Categories with real output
  // render as normal nodes; ones that ran but produced no data (no folder)
  // render as a greyed "데이터 없음" placeholder. Any present category not in
  // the run list (e.g. from an older parse) is appended after.
  const presentByName = new Map(rawCategories.map((c) => [c.name, c]));
  const orderedNames: string[] = [];
  const seenNames = new Set<string>();
  for (const artifact of selectedCase?.artifactsRun ?? []) {
    const cat = categoryForArtifact(artifact);
    if (cat === "_OVERVIEW" || seenNames.has(cat)) continue;
    seenNames.add(cat);
    orderedNames.push(cat);
  }
  const leftoverCategories = rawCategories.filter((c) => !seenNames.has(c.name));
  const hasRawSection = orderedNames.length > 0 || leftoverCategories.length > 0;

  return (
    <div
      style={{
        width: 300,
        flexShrink: 0,
        borderRight: "1px solid var(--border)",
        background: "var(--bg-panel)",
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}
    >
      <div style={{ padding: 12, borderBottom: "1px solid var(--border)" }}>
        <div style={{ position: "relative" }}>
          <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", fontSize: 13, pointerEvents: "none" }}>
            🗃️
          </span>
          <select
            value={selectedCase?.id ?? ""}
            onChange={(e) => {
              const found = cases.find((c) => c.id === e.target.value);
              if (found) onSelectCase(found);
            }}
            style={{
              width: "100%",
              padding: "7px 10px 7px 32px",
              background: "var(--bg-input)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              appearance: "none",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            <option value="" disabled>
              케이스 선택...
            </option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
        {selectedCase && (
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-faint)", display: "flex", alignItems: "center", gap: 5 }}>
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                flexShrink: 0,
                background: selectedCase.lastRunStatus === "ok" ? "var(--success)" : selectedCase.lastRunStatus === "error" ? "var(--danger)" : "var(--text-faint)",
              }}
            />
            {selectedCase.lastRunAt ? `마지막 실행: ${selectedCase.lastRunAt}` : "아직 파싱되지 않음"}
          </div>
        )}
        {selectedCase && (
          <div style={{ marginTop: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5 }}>
              <span style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                기간 필터 (사고 시점)
              </span>
              {rangeActive(timeRange) && (
                <button
                  onClick={() => onTimeRangeChange(EMPTY_TIME_RANGE)}
                  title="기간 초기화"
                  style={{ marginLeft: "auto", fontSize: 10.5, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}
                >
                  초기화 ×
                </button>
              )}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <DateTimeInput
                value={timeRange.start}
                onChange={(v) => onTimeRangeChange({ ...timeRange, start: v })}
                style={timeInputStyle}
                ariaLabel="시작 시각"
                placeholder="시작 (YYYY-MM-DD HH:mm:ss)"
              />
              <DateTimeInput
                value={timeRange.end}
                onChange={(v) => onTimeRangeChange({ ...timeRange, end: v })}
                style={timeInputStyle}
                ariaLabel="종료 시각"
                placeholder="종료 (YYYY-MM-DD HH:mm:ss)"
              />
            </div>
            {rangeActive(timeRange) && (
              <div style={{ marginTop: 5, fontSize: 10.5, color: "var(--accent)" }}>이 기간으로 모든 데이터를 거릅니다</div>
            )}
          </div>
        )}
      </div>
      <div style={{ overflowY: "auto", flex: 1 }}>
        {casesError && (
          <div style={{ padding: 16, color: "var(--danger)", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            케이스 목록을 불러오지 못했습니다.
            <br />
            {casesError}
          </div>
        )}
        {!casesError && cases.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5, lineHeight: 1.6 }}>
            등록된 케이스가 없습니다.
            <br />
            &quot;파싱 실행&quot; 탭에서 만드세요.
          </div>
        )}
        {cases.length > 0 && !selectedCase && (
          <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>케이스를 선택하세요.</div>
        )}
        {selectedCase && categories.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5, lineHeight: 1.6 }}>
            결과가 없습니다.
            <br />
            아직 파싱하지 않았을 수 있습니다.
          </div>
        )}
        {selectedCase && (
          <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
            <PinnedNavRow
              icon="🕐"
              label="통합 타임라인"
              selected={activeVirtualTab === "timeline"}
              onClick={onSelectTimeline}
            />
            <PinnedNavRow
              icon="🔖"
              label="북마크"
              count={bookmarkCount}
              selected={activeVirtualTab === "bookmarks"}
              onClick={onSelectBookmarks}
            />
          </div>
        )}
        {overviewCategory && (
          <CategoryNode
            category={overviewCategory}
            displayName="종합 분석"
            pinned
            selectedFile={selectedFile}
            onSelectFile={onSelectFile}
          />
        )}
        {hasRawSection && (
          <div style={{ padding: "10px 10px 4px", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.8 }}>
            원본 데이터
          </div>
        )}
        {orderedNames.map((name) => {
          const category = presentByName.get(name);
          return category ? (
            <CategoryNode key={category.fullPath} category={category} selectedFile={selectedFile} onSelectFile={onSelectFile} onNavigate={onNavigate} />
          ) : (
            <EmptyCategoryRow key={name} name={name} />
          );
        })}
        {leftoverCategories.map((category) => (
          <CategoryNode key={category.fullPath} category={category} selectedFile={selectedFile} onSelectFile={onSelectFile} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}
