"use client";

import { useEffect, useMemo, useState } from "react";
import type { CaseSummary, CategoryEntry, ResultFileEntry } from "@/lib/types";
import { groupKeyFor } from "@/lib/fileGrouping";

export const CATEGORY_ICONS: Record<string, string> = {
  AMCACHE: "📦",
  BROWSER: "🌐",
  EVENTLOG: "📋",
  JUMPLIST: "🔗",
  PREFETCH: "⚡",
  REGISTRY: "🗂️",
};

const OVERVIEW_TABLE_ICONS: Record<string, string> = {
  TargetInfo: "🖥️",
  ExecutionHistory: "⚡",
  RemoteAccessHistory: "🔒",
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
        gap: 8,
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
      <span style={{ display: "flex", alignItems: "center", gap: 6, overflow: "hidden", textOverflow: "ellipsis", color: selected ? "var(--text)" : "var(--text-dim)" }}>
        {icon && <span style={{ flexShrink: 0, fontSize: 12 }}>{icon}</span>}
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{file.name}</span>
      </span>
      <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{file.rowCount.toLocaleString()}</span>
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
}

function CategoryNode({ category, selectedFile, onSelectFile, displayName, pinned }: CategoryNodeProps) {
  const [expanded, setExpanded] = useState(true);
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
            : files.map((file) => (
                <FileRow
                  key={file.fullPath}
                  file={file}
                  selected={selectedFile?.fullPath === file.fullPath}
                  indent={pinned ? 20 : 26}
                  icon={pinned ? OVERVIEW_TABLE_ICONS[file.name] : undefined}
                  onSelectFile={onSelectFile}
                />
              ))}
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
}: SidebarProps) {
  const overviewCategory = categories.find((c) => c.name === "_OVERVIEW");
  const rawCategories = categories.filter((c) => c.name !== "_OVERVIEW");

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
        {rawCategories.length > 0 && (
          <div style={{ padding: "10px 10px 4px", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.8 }}>
            원본 데이터
          </div>
        )}
        {rawCategories.map((category) => (
          <CategoryNode key={category.fullPath} category={category} selectedFile={selectedFile} onSelectFile={onSelectFile} />
        ))}
      </div>
    </div>
  );
}
