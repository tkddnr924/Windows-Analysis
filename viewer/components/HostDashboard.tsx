"use client";

import { useEffect, useMemo, useState } from "react";
import CircularProgress from "@mui/material/CircularProgress";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import type { CategoryEntry, Host, ParseReport, ResultFileEntry } from "@/lib/types";
import { formatEvidenceTimestamp } from "@/lib/timeRange";

type ResultGroup = { category: CategoryEntry; files: ResultFileEntry[]; failed?: boolean };

interface Props {
  host: Host;
  categories: CategoryEntry[];
  /** Opens this exact SQLite-file/table pair; table names are not globally unique. */
  onOpenTable: (file: ResultFileEntry) => void;
  onOpenTimeline: () => void;
}

const OVERVIEW_LABELS: Record<string, string> = {
  TargetInfo: "Target Info", MFT_Records: "파일 시스템 정보", RemoteDesktopHistory: "원격 접근 이력 (RDP)",
  ExecutionHistory: "실행 이력", Defender: "Microsoft Defender 활동", RegistryFindings: "레지스트리 특이사항",
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
function formatRunTime(value: string | null): string {
  if (!value) return "기록 없음";
  return formatEvidenceTimestamp(value.replace(/Z$/, "").replace("T", " "));
}

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
  const [reportLoading, setReportLoading] = useState(true);
  // The parent obtains categories when a host result view opens. A pipeline
  // can publish after that request, leaving the dashboard with a valid report
  // but the old empty category list. Keep a local, report-triggered refresh
  // so a completed run never looks like it produced no results.
  const [resultRefreshAttempt, setResultRefreshAttempt] = useState(0);
  const [resultRefreshError, setResultRefreshError] = useState<string | null>(null);
  const [resultFileError, setResultFileError] = useState(false);
  const [resultCategorySyncPending, setResultCategorySyncPending] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setReportLoading(true);
    setLoading(true);
    setResultCategorySyncPending(false);
    setResultRefreshError(null);
    setResultFileError(false);

    void (async () => {
      let nextReport: ParseReport | null = null;
      try {
        nextReport = await window.api.parseReport(host.dir);
      } catch {
        // A missing legacy report does not prevent the existing result files
        // from being listed. The dashboard will use the parent category list.
      }
      if (cancelled) return;

      const mustSyncPublishedRun = Boolean(nextReport?.runId && nextReport.published !== false);
      // This is deliberately set before reportLoading is released. A terminal
      // report must never render against a pre-publication category snapshot.
      if (mustSyncPublishedRun) setResultCategorySyncPending(true);

      let nextCategories = categories;
      if (mustSyncPublishedRun) {
        try {
          nextCategories = await window.api.listCategories(host.dir);
        } catch {
          if (cancelled) return;
          setSavedReport(nextReport);
          setGroups([]);
          setResultRefreshError("현재 공개 결과 목록을 새로고침하지 못했습니다.");
          setResultFileError(false);
          setReportLoading(false);
          setLoading(false);
          setResultCategorySyncPending(false);
          return;
        }
      }
      if (cancelled) return;

      const nextGroups = await Promise.all(nextCategories.map(async (category) => {
        try {
          const files = await window.api.listResultFiles(category.fullPath);
          return { category, files } satisfies ResultGroup;
        } catch {
          return { category, files: [], failed: true } satisfies ResultGroup;
        }
      }));
      if (cancelled) return;

      // Commit the report and the exact category/file snapshot together. This
      // preserves the last run's identity through the full refresh, rather
      // than allowing a successful category request to clear the loader while
      // its file listing is still pending.
      setSavedReport(nextReport);
      setGroups(nextGroups);
      setResultRefreshError(null);
      setResultFileError(nextGroups.some((group) => group.failed));
      setReportLoading(false);
      setLoading(false);
      setResultCategorySyncPending(false);
    })();
    return () => { cancelled = true; };
  }, [categories, host.dir, host.lastRunAt, host.lastRunStatus, resultRefreshAttempt]);

  const report = useMemo(() => {
    const groupByCategory = new Map(groups.map((group) => [group.category.name, group]));
    const overview = groupByCategory.get("_OVERVIEW")?.files ?? [];
    const artifactNames = savedReport?.artifacts.length
      ? savedReport.artifacts.map((artifact) => artifact.name)
      : (host.artifactsRun ?? []);
    const artifacts = artifactNames.map((name) => {
      const target = outputForArtifact(name);
      const group = groupByCategory.get(target.category);
      const files = target.table ? (group?.files.filter((file) => file.tableName === target.table) ?? []) : (group?.files ?? []);
      const saved = savedReport?.artifacts.find((artifact) => artifact.name === name);
      // A parser reaching `completed` is not enough to make a result
      // navigable.  On a partial run only sealed raw SQLite files recorded in
      // `publishedOutputs` were copied to the live host directory.  Resolve
      // controls from that immutable manifest, not from a category's older
      // files (which may include a retained overview or an unpublished MFT).
      const publishedFiles = saved?.publishedOutputs === undefined
        ? []
        : files.filter((file) => isPublishedArtifactOutput(target.category, file.relativePath, saved?.publishedOutputs ?? []));
      return { name, files, saved, publishedFiles };
    });
    return {
      artifacts,
      // Failed, cancelled, and partial runs may leave an earlier overview on
      // disk. Never present that older derived table as an output of the
      // current lifecycle; legacy manifests without this field keep the
      // pre-existing file-list behavior.
      overviewTables: savedReport?.published === false || savedReport?.status === "partial"
        ? []
        : overview.filter((file) => file.tableName !== "TargetInfo"),
    };
  }, [groups, host.artifactsRun, savedReport]);

  const overviewFiles = groups.find((group) => group.category.name === "_OVERVIEW")?.files ?? [];
  if (loading || reportLoading || resultCategorySyncPending) return <Loading />;

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

      {savedReport && <RunPublicationSummary report={savedReport} />}
      {(resultRefreshError || resultFileError) && (
        <section role="alert" style={{ marginTop: 10, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, padding: "8px 10px", borderLeft: "3px solid var(--text-faint)", color: "var(--text-dim)", fontSize: 12.5 }}>
          <span>{resultRefreshError ?? "일부 공개 결과 파일을 불러오지 못했습니다."}</span>
          <button type="button" onClick={() => setResultRefreshAttempt((attempt) => attempt + 1)} style={retryButtonStyle}>다시 시도</button>
        </section>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 3fr) minmax(300px, 1fr)", gap: 14, marginTop: 14, alignItems: "start" }}>
        <section style={panelStyle}>
          <SectionHeader title="실행한 파서" />
          {report.artifacts.length === 0 ? <Empty>실행한 파서 기록이 없습니다.</Empty> : (
            <div>
              {report.artifacts.map((artifact) => <ArtifactRow key={artifact.name} name={artifact.name} files={artifact.files} publishedFiles={artifact.publishedFiles} saved={artifact.saved} registryRecoveryDisabled={savedReport?.registryRecovery?.mode === "disabled"} onOpenTable={onOpenTable} />)}
            </div>
          )}
        </section>

        <section style={panelStyle}>
          <SectionHeader title="현재 공개된 분석 결과" />
          {report.overviewTables.length === 0 ? <Empty>{resultRefreshError || resultFileError ? "공개 결과 목록을 확인하지 못했습니다. 다시 시도하세요." : savedReport?.status === "partial" ? "부분 완료 실행에서는 종합 분석을 다시 만들지 않았습니다. 공개된 원본 아티팩트는 왼쪽 목록에서 확인합니다." : savedReport?.status === "cancelled" ? "최근 실행이 취소되어 이번 실행의 분석 결과는 공개되지 않았습니다." : savedReport?.status === "error" ? "최근 실행이 오류로 종료되어 이번 실행의 분석 결과는 공개되지 않았습니다." : "생성된 분석 결과가 없습니다."}</Empty> : (
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

function RunPublicationSummary({ report }: { report: ParseReport }) {
  const inputCount = report.artifacts.reduce((count, artifact) => count + artifact.inputs.length, 0);
  const outputCount = report.publishedOutputs?.length ?? 0;
  const registryRecoveryDisabled = report.registryRecovery?.mode === "disabled";
  const discoveredRegistryLogs = report.registryHives?.reduce((count, hive) => count + (hive.recoveryLogsDiscovered ?? 0), 0) ?? 0;
  const recoveryPolicy = registryRecoveryDisabled && (
    <div style={{ marginTop: 3, color: "var(--text-faint)" }}>
      레지스트리 복구 미적용{discoveredRegistryLogs > 0 ? ` · 트랜잭션 로그 ${discoveredRegistryLogs.toLocaleString()}개 발견 · 미적용` : ""}
    </div>
  );
  // Keep normal completion compact, but make the durable manifest's actual
  // evidence/result counts explicit. This prevents an in-progress category
  // refresh from being mistaken for a zero-input or zero-output parse.
  if (report.status === "ok") {
    return <section aria-label="최근 실행 공개 상태" style={{ marginTop: 14, padding: "8px 10px", borderLeft: "3px solid var(--success)", color: "var(--text-dim)", fontSize: 12.5 }}>
      <div>완료 · 입력 {inputCount.toLocaleString()}개 · 공개 결과 파일 {outputCount.toLocaleString()}개</div>
      {recoveryPolicy}
    </section>;
  }
  const status = report.status === "partial" ? "부분 완료" : report.status === "error" ? "오류" : "취소됨";
  const color = report.status === "error" ? "var(--danger)" : report.status === "partial" ? "var(--warning)" : "var(--text-dim)";
  const hasPublicationMetadata = report.published !== undefined;
  const published = report.published && (report.publishedOutputs?.length ?? 0) > 0;
  return <section aria-label="최근 실행 공개 상태" style={{ marginTop: 14, padding: "8px 10px", borderLeft: `3px solid ${color}`, color: "var(--text-dim)", fontSize: 12.5 }}>
    <span>{status} · {!hasPublicationMetadata ? "기존 보고서의 공개 상태를 확인할 수 없습니다." : published ? `공개된 원본 결과 ${report.publishedArtifacts?.join(", ") || `${report.publishedOutputs?.length ?? 0}개 파일`}` : "이번 실행에서 공개된 결과 없음"}</span>
    {recoveryPolicy}
  </section>;
}

function SectionHeader({ title }: { title: string }) {
  return <div style={{ paddingBottom: 10, borderBottom: "1px solid var(--border-subtle)" }}><h2 style={{ margin: 0, color: "var(--text)", fontSize: 17, letterSpacing: "-0.025em" }}>{title}</h2></div>;
}

function isPublishedArtifactOutput(category: string, relativePath: string, publishedOutputs: string[]): boolean {
  const candidate = `${category}/${relativePath}`.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
  return publishedOutputs.some((output) => output.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase() === candidate);
}

function ArtifactRow({ name, files, publishedFiles, saved, registryRecoveryDisabled, onOpenTable }: {
  name: string;
  files: ResultFileEntry[];
  publishedFiles: ResultFileEntry[];
  saved?: ParseReport["artifacts"][number];
  registryRecoveryDisabled: boolean;
  onOpenTable: (file: ResultFileEntry) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasPublicationMetadata = saved?.publishedOutputs !== undefined;
  const hasOutput = saved ? hasPublicationMetadata ? (saved.publishedOutputs?.length ?? 0) > 0 : files.length > 0 : files.length > 0;
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
        <StatusBadge hasOutput={hasOutput} saved={saved} />
      </button>
      {expanded && (
        <div style={{ padding: "4px 12px 11px 28px", background: "rgba(7, 13, 20, 0.20)" }}>
          {publishedFiles.length > 0 && (
            <div style={{ display: "grid", gap: 5, margin: "5px 0 10px" }} aria-label={`${name}에서 이번 실행에 공개된 원본 결과`}>
              <span style={{ color: "var(--text-faint)", fontSize: 12.5 }}>이번 실행에 공개된 원본 결과</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {publishedFiles.map((file) => (
                  <button
                    key={`${file.relativePath}:${file.tableName}`}
                    type="button"
                    onClick={() => onOpenTable(file)}
                    title={`${file.fileName} · ${file.tableName} 열기`}
                    style={publishedTableButtonStyle}
                  >
                    {file.tableName}
                  </button>
                ))}
              </div>
            </div>
          )}
          <ArtifactDetails inputs={savedInputs} hasStoredCounts={hasStoredCounts} noInput={isNoInputArtifact(saved)} registryRecoveryDisabled={registryRecoveryDisabled && name === "Registry"} />
        </div>
      )}
    </div>
  );
}

function isNoInputArtifact(saved?: ParseReport["artifacts"][number]) {
  return saved?.status === "no_input" || (saved?.inputDiscoveryChecked === true && saved.evidenceDiscovered !== true && (saved.outputs?.length ?? 0) === 0);
}

function StatusBadge({ hasOutput, saved }: { hasOutput: boolean; saved?: ParseReport["artifacts"][number] }) {
  const state = saved?.status;
  const noInput = isNoInputArtifact(saved);
  const label = noInput ? "원본 미수집" : state === "failed" ? "실패 · 미공개" : hasOutput ? "공개됨" : state === "completed" ? "완료 · 미공개" : "출력 없음";
  const color = state === "failed" ? "var(--danger)" : noInput ? "var(--text-dim)" : state === "completed" && !hasOutput ? "var(--warning)" : hasOutput ? "var(--success)" : "var(--text-faint)";
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 8px", border: `1px solid color-mix(in srgb, ${color} 45%, var(--border))`, borderRadius: "var(--radius-sm)", background: "transparent", color, fontSize: 12.5, fontWeight: 650 }}>{label}</span>;
}

function ArtifactDetails({ inputs, hasStoredCounts, noInput, registryRecoveryDisabled }: { inputs: ParseReport["artifacts"][number]["inputs"]; hasStoredCounts: boolean; noInput: boolean; registryRecoveryDisabled: boolean }) {
  if (noInput) return <div style={{ padding: "6px 0", color: "var(--text-faint)", fontSize: 13 }}>원본 미수집 · 이번 실행 결과 없음</div>;
  if (!hasStoredCounts) return <div style={{ padding: "6px 0", color: "var(--text-faint)", fontSize: 13 }}>파일별 추출 건수는 이 호스트를 다시 파싱한 뒤 표시됩니다.</div>;
  if (inputs.length === 0) return <div style={{ padding: "6px 0", color: "var(--text-faint)", fontSize: 13 }}>파서가 읽은 증거 파일이 없습니다.</div>;
  return (
    <div>
      {inputs.map((input) => <DetailLine key={input.sourcePath ?? input.name} name={input.name} recordCount={input.recordCount ?? 0} recoveryLog={input.recoveryLog === true} registryRecoveryDisabled={registryRecoveryDisabled} />)}
    </div>
  );
}

function DetailLine({ name, recordCount, recoveryLog, registryRecoveryDisabled }: { name: string; recordCount: number; recoveryLog: boolean; registryRecoveryDisabled: boolean }) {
  const recoveryLabel = recoveryLog
    ? registryRecoveryDisabled ? "트랜잭션 로그 발견 · 미적용" : "복구 로그 적용"
    : `${recordCount.toLocaleString()}건 추출`;
  return <div style={{ display: "grid", gridTemplateColumns: "minmax(180px, 0.65fr) minmax(130px, 0.35fr)", gap: 16, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{name}</span><span style={{ color: recoveryLog ? "var(--text-faint)" : "var(--accent)", fontSize: 13, fontWeight: recoveryLog ? 500 : 650, textAlign: "right" }}>{recoveryLabel}</span></div>;
}

function Empty({ children }: { children: React.ReactNode }) { return <div style={{ padding: "20px 0 7px", color: "var(--text-faint)", fontSize: 14 }}>{children}</div>; }

const panelStyle: React.CSSProperties = { background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-card)", padding: "16px 18px" };
const timelineButtonStyle: React.CSSProperties = { padding: "9px 14px", background: "var(--accent-subtle)", color: "var(--accent)", border: "1px solid rgba(103, 178, 255, 0.58)", borderRadius: "var(--radius-sm)", cursor: "pointer", fontWeight: 650, fontSize: 14, whiteSpace: "nowrap" };
const tableRowStyle: React.CSSProperties = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, width: "100%", padding: "11px 1px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", fontSize: 14.5, fontWeight: 600 };
const artifactButtonStyle: React.CSSProperties = { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, width: "100%", minHeight: 48, padding: "9px 2px", background: "transparent", border: 0, color: "var(--text)", cursor: "pointer", fontSize: 15, fontWeight: 650, textAlign: "left" };
const publishedTableButtonStyle: React.CSSProperties = { minHeight: 30, padding: "4px 8px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-raised)", color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5, fontWeight: 650 };
const retryButtonStyle: React.CSSProperties = { minHeight: 28, padding: "3px 8px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-raised)", color: "var(--text)", cursor: "pointer", fontSize: 12.5, fontWeight: 650, whiteSpace: "nowrap" };
