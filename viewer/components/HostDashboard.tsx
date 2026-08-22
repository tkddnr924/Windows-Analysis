"use client";

import { useEffect, useMemo, useState } from "react";
import CircularProgress from "@mui/material/CircularProgress";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import type { CategoryEntry, Host, ParseReport, ResultFileEntry } from "@/lib/types";

type ResultGroup = { category: CategoryEntry; files: ResultFileEntry[] };

interface Props {
  host: Host;
  categories: CategoryEntry[];
  onOpenTable: (name: string) => void;
  onOpenTimeline: () => void;
}

const OVERVIEW_LABELS: Record<string, string> = {
  TargetInfo: "Target Info", MFT_Records: "파일 시스템 정보", RemoteDesktopHistory: "원격 접근 이력 (RDP)",
  ExecutionHistory: "실행 이력", Defender: "Defender", RegistryFindings: "레지스트리 특이사항",
  PowerShellHistory: "파워셸 실행 이력", SmbHistory: "SMB 접속 이력", ScheduledTasks: "작업 스케줄러",
  RdpCache: "RDP Cache", BrowserActivity: "브라우저 활동",
};

const ARTIFACT_OUTPUT: Record<string, { category: string; table?: string }> = {
  UsnJrnl: { category: "FILESYSTEM" },
  MFT: { category: "_OVERVIEW", table: "MFT_Records" },
  BrowserHistory: { category: "BROWSER" },
  BrowserCache: { category: "BROWSER" },
};

function outputForArtifact(name: string) { return ARTIFACT_OUTPUT[name] ?? { category: name.toUpperCase() }; }
function formatRunTime(value: string | null): string { return value ? value.replace("T", " ").replace(/\.\d+Z?$/, "") : "기록 없음"; }

function ComputerName({ files, host }: { files: ResultFileEntry[]; host: Host }) {
  const [computer, setComputer] = useState(host.name || "호스트");

  useEffect(() => {
    const targetInfo = files.find((file) => file.tableName === "TargetInfo");
    if (!targetInfo) { setComputer(host.name || "호스트"); return; }

    let cancelled = false;
    window.api.readResultFile(targetInfo.fullPath, targetInfo.tableName)
      .then((data) => {
        const name = data.rows.find((row) => row.category === "SystemInfo" && row.name === "ComputerName")?.value;
        if (!cancelled) setComputer(name || host.name || "호스트");
      })
      .catch(() => { if (!cancelled) setComputer(host.name || "호스트"); });
    return () => { cancelled = true; };
  }, [files, host.id, host.name]);

  return <h1 style={{ margin: 0, color: "var(--text)", fontSize: 29, lineHeight: 1.16, letterSpacing: "-0.045em", fontWeight: 760 }}>{computer}</h1>;
}

export default function HostDashboard({ host, categories, onOpenTable, onOpenTimeline }: Props) {
  const [groups, setGroups] = useState<ResultGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [savedReport, setSavedReport] = useState<ParseReport | null>(null);

  useEffect(() => {
    let cancelled = false;
    window.api.parseReport(host.dir).then((report) => {
      if (!cancelled) setSavedReport(report);
    }).catch(() => {
      if (!cancelled) setSavedReport(null);
    });
    return () => { cancelled = true; };
  }, [host.dir]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all(categories.map(async (category) => {
      try {
        const files = await window.api.listResultFiles(category.fullPath);
        return { category, files } satisfies ResultGroup;
      } catch {
        return { category, files: [] } satisfies ResultGroup;
      }
    })).then((nextGroups) => {
      if (!cancelled) { setGroups(nextGroups); setLoading(false); }
    });
    return () => { cancelled = true; };
  }, [categories, host.id]);

  const report = useMemo(() => {
    const groupByCategory = new Map(groups.map((group) => [group.category.name, group]));
    const overview = groupByCategory.get("_OVERVIEW")?.files ?? [];
    const artifacts = (host.artifactsRun ?? []).map((name) => {
      const target = outputForArtifact(name);
      const group = groupByCategory.get(target.category);
      const files = target.table ? (group?.files.filter((file) => file.tableName === target.table) ?? []) : (group?.files ?? []);
      const saved = savedReport?.artifacts.find((artifact) => artifact.name === name);
      return { name, files, saved };
    });
    return {
      artifacts,
      overviewTables: overview.filter((file) => file.tableName !== "TargetInfo"),
    };
  }, [groups, host.artifactsRun, savedReport]);

  const overviewFiles = groups.find((group) => group.category.name === "_OVERVIEW")?.files ?? [];
  if (loading) return <Loading />;

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "22px 26px 28px" }}>
      <header style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 18, padding: "2px 0 15px", borderBottom: "1px solid var(--border)" }}>
        <div>
          <ComputerName files={overviewFiles} host={host} />
          <div style={{ marginTop: 6, color: "var(--text-dim)", fontSize: 14 }}>
            마지막 파싱 <span style={{ color: "var(--text-faint)" }}>{formatRunTime(host.lastRunAt)}</span>
          </div>
        </div>
        <button onClick={onOpenTimeline} style={timelineButtonStyle}>통합 타임라인 보기</button>
      </header>

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 3fr) minmax(300px, 1fr)", gap: 14, marginTop: 14, alignItems: "start" }}>
        <section style={panelStyle}>
          <SectionHeader title="실행한 파서" />
          {report.artifacts.length === 0 ? <Empty>실행한 파서 기록이 없습니다.</Empty> : (
            <div>
              {report.artifacts.map((artifact) => <ArtifactRow key={artifact.name} name={artifact.name} files={artifact.files} saved={artifact.saved} />)}
            </div>
          )}
        </section>

        <section style={panelStyle}>
          <SectionHeader title="분석 결과 테이블" />
          {report.overviewTables.length === 0 ? <Empty>생성된 분석 결과가 없습니다.</Empty> : (
            <div>{report.overviewTables.map((table) => (
              <div key={`${table.fileName}:${table.tableName}`} style={tableRowStyle}>
                <span>{OVERVIEW_LABELS[table.tableName] ?? table.tableName}</span>
                <span>{table.rowCount.toLocaleString()}건</span>
              </div>
            ))}</div>
          )}
        </section>
      </div>
    </div>
  );
}

function Loading() {
  return <div role="status" aria-live="polite" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, height: "100%", color: "var(--text-dim)", fontSize: 15 }}><CircularProgress size={20} thickness={4.5} aria-label="파싱 결과를 불러오는 중" sx={{ color: "var(--accent)" }} /><span>파싱 결과를 확인하는 중...</span></div>;
}

function SectionHeader({ title }: { title: string }) {
  return <div style={{ paddingBottom: 10, borderBottom: "1px solid var(--border-subtle)" }}><h2 style={{ margin: 0, color: "var(--text)", fontSize: 17, letterSpacing: "-0.025em" }}>{title}</h2></div>;
}

function ArtifactRow({ name, files, saved }: { name: string; files: ResultFileEntry[]; saved?: ParseReport["artifacts"][number] }) {
  const [expanded, setExpanded] = useState(false);
  const hasOutput = saved ? saved.status === "completed" : files.length > 0;
  const savedInputs = saved?.inputs ?? [];
  const hasStoredCounts = savedInputs.some((input) => typeof input.recordCount === "number");
  return (
    <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
      <button
        type="button"
        onClick={() => setExpanded((value) => !value)}
        aria-expanded={expanded}
        style={artifactButtonStyle}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
          {expanded ? <KeyboardArrowDownIcon sx={{ fontSize: 19, color: "var(--text-faint)" }} /> : <KeyboardArrowRightIcon sx={{ fontSize: 19, color: "var(--text-faint)" }} />}
          <span>{name}</span>
        </span>
        <StatusBadge hasOutput={hasOutput} />
      </button>
      {expanded && (
        <div style={{ padding: "4px 12px 11px 28px", background: "rgba(7, 13, 20, 0.20)" }}>
          <ArtifactDetails inputs={savedInputs} hasStoredCounts={hasStoredCounts} />
        </div>
      )}
    </div>
  );
}

function StatusBadge({ hasOutput }: { hasOutput: boolean }) {
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 8px", border: `1px solid ${hasOutput ? "rgba(63, 185, 80, 0.32)" : "var(--border)"}`, borderRadius: 999, background: hasOutput ? "var(--success-subtle)" : "transparent", color: hasOutput ? "var(--success)" : "var(--text-faint)", fontSize: 12.5, fontWeight: 650 }}><span style={{ width: 5, height: 5, borderRadius: "50%", background: hasOutput ? "var(--success)" : "var(--text-faint)" }} />{hasOutput ? "결과 있음" : "출력 없음"}</span>;
}

function ArtifactDetails({ inputs, hasStoredCounts }: { inputs: ParseReport["artifacts"][number]["inputs"]; hasStoredCounts: boolean }) {
  if (!hasStoredCounts) return <div style={{ padding: "6px 0", color: "var(--text-faint)", fontSize: 13 }}>파일별 추출 건수는 이 호스트를 다시 파싱한 뒤 표시됩니다.</div>;
  if (inputs.length === 0) return <div style={{ padding: "6px 0", color: "var(--text-faint)", fontSize: 13 }}>파서가 읽은 증거 파일이 없습니다.</div>;
  return (
    <div>
      {inputs.map((input) => <DetailLine key={input.sourcePath ?? input.name} name={input.name} recordCount={input.recordCount ?? 0} recoveryLog={input.recoveryLog === true} />)}
    </div>
  );
}

function DetailLine({ name, recordCount, recoveryLog }: { name: string; recordCount: number; recoveryLog: boolean }) {
  return <div style={{ display: "grid", gridTemplateColumns: "minmax(180px, 0.65fr) minmax(130px, 0.35fr)", gap: 16, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{name}</span><span style={{ color: recoveryLog ? "var(--text-faint)" : "var(--accent)", fontSize: 13, fontWeight: recoveryLog ? 500 : 650, textAlign: "right" }}>{recoveryLog ? "복구 로그 적용" : `${recordCount.toLocaleString()}건 추출`}</span></div>;
}

function Empty({ children }: { children: React.ReactNode }) { return <div style={{ padding: "20px 0 7px", color: "var(--text-faint)", fontSize: 14 }}>{children}</div>; }

const panelStyle: React.CSSProperties = { background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-card)", padding: "16px 18px" };
const timelineButtonStyle: React.CSSProperties = { padding: "9px 14px", background: "var(--accent-subtle)", color: "var(--accent)", border: "1px solid rgba(103, 178, 255, 0.58)", borderRadius: "var(--radius-sm)", cursor: "pointer", fontWeight: 650, fontSize: 14, whiteSpace: "nowrap" };
const tableRowStyle: React.CSSProperties = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, width: "100%", padding: "11px 1px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", fontSize: 14.5, fontWeight: 600 };
const artifactButtonStyle: React.CSSProperties = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, width: "100%", minHeight: 48, padding: "9px 2px", background: "transparent", border: 0, color: "var(--text)", cursor: "pointer", fontSize: 15, fontWeight: 650, textAlign: "left" };
