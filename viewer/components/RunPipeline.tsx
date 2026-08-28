"use client";
import PaginationControls from "@/components/PaginationControls";

import { useEffect, useId, useMemo, useState } from "react";
import AddIcon from "@mui/icons-material/Add";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutlineOutlined";
import DeselectIcon from "@mui/icons-material/Deselect";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutlineOutlined";
import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import MemoryOutlinedIcon from "@mui/icons-material/MemoryOutlined";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SelectAllIcon from "@mui/icons-material/SelectAll";
import TaskAltIcon from "@mui/icons-material/TaskAlt";
import TimerOutlinedIcon from "@mui/icons-material/TimerOutlined";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import type { Case, Host, ParseReport } from "@/lib/types";
import { isHostReportSyncPending, selectVisibleHostReport, shouldLoadHostReport, type HostReportCacheEntry } from "@/lib/hostReportCache";
import type { PipelineRun, PipelineRunItem } from "@/lib/usePipelineRun";
import { formatEvidenceTimestamp } from "@/lib/timeRange";
import { useModalDialog } from "@/lib/useModalDialog";

interface RunPipelineProps {
  activeCase: Case;
  onChanged: () => void;
  onOpenHost: (h: Host) => void;
  /** Shared parse state, hoisted to Home so it survives screen changes. */
  run: PipelineRun;
}

const primaryButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 5,
  padding: "7px 16px",
  background: "var(--accent-emphasis)",
  color: "#eaf3ff",
  fontWeight: 600,
  border: "none",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  whiteSpace: "nowrap",
};

const dangerButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 5,
  padding: "7px 16px",
  background: "var(--danger)",
  color: "#fff1ef",
  border: "none",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  whiteSpace: "nowrap",
};

const neutralButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 5,
  padding: "7px 16px",
  background: "var(--bg-elevated)",
  color: "var(--text)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  whiteSpace: "nowrap",
};

const linkButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
  marginLeft: 10,
  fontSize: 11,
  background: "transparent",
  border: "none",
  color: "var(--accent)",
  cursor: "pointer",
  fontWeight: 600,
};

const HOSTS_PER_PAGE = 10;

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

// "45초" / "3분 12초" / "1시간 4분" from a duration in seconds.
function formatDuration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return `${s}초`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}분 ${s % 60}초`;
  return `${Math.floor(m / 60)}시간 ${m % 60}분`;
}

function StatusPill({ status }: { status: string | null }) {
  if (status === "running")
    return <span style={statusPillStyle("var(--accent)", "var(--accent-subtle)")}><CircularProgress size={11} thickness={5} />실행 중</span>;
  if (status === "queued")
    return <span style={statusPillStyle("var(--text-dim)", "var(--bg-elevated)")}><TimerOutlinedIcon sx={{ fontSize: 13 }} />대기 중</span>;
  if (status === "ok" || status === "complete")
    return <span style={statusPillStyle("var(--success)", "var(--success-subtle)")}><TaskAltIcon sx={{ fontSize: 13 }} />완료</span>;
  if (status === "error")
    return <span style={statusPillStyle("var(--danger)", "var(--danger-subtle)")}><ErrorOutlineIcon sx={{ fontSize: 13 }} />오류</span>;
  if (status === "partial")
    return <span style={statusPillStyle("var(--warning)", "var(--warning-subtle)")}><ErrorOutlineIcon sx={{ fontSize: 13 }} />부분 완료</span>;
  if (status === "cancelled")
    return <span style={statusPillStyle("var(--text-dim)", "var(--bg-elevated)")}><CancelOutlinedIcon sx={{ fontSize: 13 }} />취소됨</span>;
  return <span style={statusPillStyle("var(--text-faint)", "var(--bg-elevated)")}><TimerOutlinedIcon sx={{ fontSize: 13 }} />미실행</span>;
}

function statusPillStyle(color: string, _background: string): React.CSSProperties {
  // 라벨은 아웃라인 스타일 — 채움 배경 대신 색 테두리 + 투명 배경.
  return { display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 4, fontSize: 11, fontWeight: 600, color, background: "transparent", border: `1px solid color-mix(in srgb, ${color} 55%, transparent)`, padding: "2px 8px", borderRadius: "var(--radius-sm)", textAlign: "center" };
}

function folderName(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  return trimmed.split(/[\\/]/).pop() ?? "";
}

function InlineParseProgress({
  stepLabel,
  percent,
  completedSteps,
  totalSteps,
}: {
  stepLabel: string;
  percent: number;
  completedSteps: number;
  totalSteps: number;
}) {
  const color = "var(--accent)";
  const label = stepLabel.replace(/…$/, "");
  return (
    <div style={{ padding: "4px 0 8px", display: "flex", flexDirection: "column", gap: 7 }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color }}>
          {label}<span className="parse-progress__dots" aria-label="진행 중">...</span>
        </span>
        <span style={{ fontSize: 20, fontWeight: 700, fontVariantNumeric: "tabular-nums", color }}>{percent}%</span>
      </div>
      <div className="parse-progress__track">
        <div className="parse-progress__fill" style={{ width: `${percent}%`, background: color }} />
      </div>
      <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>
        {totalSteps > 0 ? `${Math.min(completedSteps, totalSteps)} / ${totalSteps} 단계` : "파싱 준비 중"}
      </span>
    </div>
  );
}

function activeRunForHost(runs: PipelineRunItem[], hostId: string): PipelineRunItem | undefined {
  // A re-run may be queued after an active invocation of the same host. Show
  // the actually running invocation first; never let a later queued entry
  // erase progress that is already arriving from the parser.
  return [...runs].reverse().find((run) => run.hostId === hostId && run.status === "running")
    ?? [...runs].reverse().find((run) => run.hostId === hostId && run.status === "queued");
}

function terminalRunForHost(runs: PipelineRunItem[], hostId: string): PipelineRunItem | undefined {
  return [...runs].reverse().find((run) => run.hostId === hostId
    && (run.status === "complete" || run.status === "partial" || run.status === "error" || run.status === "cancelled"));
}

function terminalStatusLabel(status: string): string {
  if (status === "ok" || status === "complete") return "완료";
  if (status === "partial") return "부분 완료";
  if (status === "error") return "오류";
  return "취소";
}

function RunLogDetail({ host, report, autoOpen = false }: { host: Host; report: ParseReport; autoOpen?: boolean }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  // 부모 패널이 열리며 마운트되는 경우엔 클릭 한 번으로 바로 로그를 보여준다.
  useEffect(() => {
    if (autoOpen && report.runId) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!report.runId) return null;
  async function load() {
    setOpen(true);
    setLoaded(false);
    setError(null);
    try {
      const preview = await window.api.parseRunLog(host.dir, report.runId!);
      setText(preview.text);
      setTruncated(preview.truncated);
      setLoaded(true);
    } catch (cause) {
      setError(errorMessage(cause, "실행 로그를 불러오지 못했습니다."));
    }
  }
  const copy = async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  return <div style={{ display: "grid", gap: 5, marginTop: 2 }}>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {!autoOpen && <button className="nm-btn" type="button" aria-label={`${host.name} 실행 로그 ${open ? "닫기" : "보기"}`} onClick={open ? () => setOpen(false) : () => void load()} style={{ ...neutralButtonStyle, width: "fit-content", padding: "4px 8px", fontSize: 11.5 }}>{open ? "실행 로그 닫기" : "실행 로그 보기"}</button>}
      {open && text && <button className="nm-btn" type="button" onClick={copy} style={{ ...neutralButtonStyle, width: "fit-content", padding: "4px 8px", fontSize: 11.5 }}>로그 복사</button>}
    </div>
    {copyState === "copied" && <span role="status">로그를 복사했습니다.</span>}
    {copyState === "failed" && <span role="alert">로그 복사에 실패했습니다.</span>}
    {open && !loaded && !error && <span role="status">로그를 불러오는 중…</span>}
    {error && <span role="alert" style={{ color: "var(--danger)" }}>{error} <button type="button" onClick={() => void load()} style={linkButtonStyle}>다시 시도</button></span>}
    {open && loaded && <pre aria-label={`${host.name} 실행 로그 내용`} style={{ maxHeight: 168, overflow: "auto", margin: 0, padding: "8px 10px", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{text || "기록된 로그 행이 없습니다."}{truncated ? "\n\n… 앞부분 24KB만 표시합니다." : ""}</pre>}
  </div>;
}

function RunOutcomeSummary({
  host,
  report,
  onRetryMft,
}: {
  host: Host;
  report?: ParseReport;
  onRetryMft?: () => void;
}) {
  const duration = host.lastRunDurationSecs ?? 0;
  const terminalStatus = report?.status ?? host.lastRunStatus;
  const failed = terminalStatus === "error";
  const partial = terminalStatus === "partial";
  const cancelled = terminalStatus === "cancelled";
  const mft = report?.artifacts.find((artifact) => artifact.name === "MFT");
  // 정상 완료 실행도 로그를 볼 수 있어야 한다 — 항상 렌더.
  const retryMft = report?.status === "partial" && report.artifacts.some((artifact) => artifact.name === "MFT" && artifact.status === "failed");
  const summaryColor = failed ? "var(--danger)" : partial ? "var(--warning)" : cancelled ? "var(--text-dim)" : "var(--success)";
  // 오류 원문은 여기에 표기하지 않는다 — 세부 내용은 실행 로그로 확인한다.
  return <RunOutcomeSummaryBody summaryColor={summaryColor} duration={duration} mft={mft} host={host} report={report} retryMft={retryMft} onRetryMft={onRetryMft} />;
}

function RunOutcomeSummaryBody({ summaryColor, duration, mft, host, report, retryMft, onRetryMft }: { summaryColor: string; duration: number; mft?: { status: string }; host: Host; report?: ParseReport; retryMft: boolean; onRetryMft?: () => void }) {
  const [open, setOpen] = useState(false);
  return <div style={{ margin: "2px 0 0", fontSize: 12 }}>
    <button type="button" className="nm-btn" aria-expanded={open} onClick={() => setOpen((value) => !value)} style={{ cursor: "pointer", width: "fit-content", display: "inline-flex", alignItems: "center", gap: 7, padding: "3px 11px", minHeight: 26, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text-dim)", fontSize: 11.5, fontWeight: 600, whiteSpace: "nowrap" }}>
      <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%", background: summaryColor }} />
      실행 로그
      <span style={{ color: "var(--text-faint)", fontWeight: 500 }}>총 소요 {formatDuration(duration)}</span>
    </button>
    {open && <div style={{ display: "grid", gap: 6, marginTop: 8, padding: "10px 12px", color: "var(--text-dim)", border: "1px solid var(--border)", borderLeft: `3px solid ${summaryColor}`, borderRadius: "var(--radius-md)", background: "var(--bg)" }}>
      {mft?.status === "no_input" && <span>MFT: 원본 $MFT 파일 미수집 · 이번 실행에서는 결과를 만들지 않았습니다.</span>}
      {mft?.status === "failed" && <span>MFT: 파싱 실패 · MFT 결과는 공개되지 않았습니다.</span>}
      {report && <RunLogDetail host={host} report={report} autoOpen />}
      {retryMft && onRetryMft && <button className="nm-btn" type="button" onClick={onRetryMft} style={{ ...neutralButtonStyle, width: "fit-content", padding: "4px 8px", fontSize: 11.5 }}>MFT만 재시도</button>}
      {!report && <span>세부 보고서를 불러오는 중이거나 이전 실행에는 구조화된 보고서가 없습니다.</span>}
    </div>}
  </div>;
}

function RenameHostDialog({
  value,
  saving,
  error,
  onChange,
  onClose,
  onSave,
}: {
  value: string;
  saving: boolean;
  error: string | null;
  onChange: (value: string) => void;
  onClose: () => void;
  onSave: () => void;
}) {
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);
  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1400, display: "grid", placeItems: "center", padding: 18, background: "rgba(0, 0, 0, 0.46)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} onClick={(event) => event.stopPropagation()} className="dfir-surface" style={{ width: "min(420px, 100%)", padding: 18 }}>
      <form onSubmit={(event) => { event.preventDefault(); onSave(); }}>
      <h2 id={titleId} style={{ margin: "0 0 6px", fontSize: 15 }}>호스트 이름 변경</h2>
      <p style={{ margin: "0 0 14px", color: "var(--text-dim)", fontSize: 12.5 }}>표시 이름만 바뀝니다. 수집 원본, 결과, 북마크 경로는 변경되지 않습니다.</p>
      <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-dim)" }}>호스트 이름
        <input data-dialog-autofocus value={value} onChange={(event) => onChange(event.target.value)} disabled={saving} style={{ padding: "8px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)" }} />
      </label>
      {error && <div role="alert" style={{ marginTop: 9, color: "var(--danger)", fontSize: 12 }}>{error}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
          <button type="button" onClick={onClose} disabled={saving} style={{ ...linkButtonStyle, marginLeft: 0 }}>취소</button>
          <button className="nm-btn" type="submit" disabled={saving || !value.trim()} style={{ ...primaryButtonStyle, opacity: saving || !value.trim() ? .5 : 1 }}>{saving ? "저장 중" : "변경"}</button>
        </div>
      </form>
    </div>
  </div>;
}

export default function RunPipeline({ activeCase, onChanged, onOpenHost, run }: RunPipelineProps) {
  const hosts = activeCase.hosts;

  const [newHostName, setNewHostName] = useState("");
  const [newHostTarget, setNewHostTarget] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [artifacts, setArtifacts] = useState<string[]>([]);
  const [artifactLoading, setArtifactLoading] = useState(true);
  const [artifactLoadAttempt, setArtifactLoadAttempt] = useState(0);
  const [selectedArtifacts, setSelectedArtifacts] = useState<Set<string>>(new Set());
  const [artifactControlsExpanded, setArtifactControlsExpanded] = useState(false);
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [hostQuery, setHostQuery] = useState("");
  const [hostPage, setHostPage] = useState(0);
  const [renameHost, setRenameHost] = useState<Host | null>(null);
  const [renameName, setRenameName] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [reportsByHost, setReportsByHost] = useState<Record<string, HostReportCacheEntry<ParseReport>>>({});

  // The parse state (runningHostId, logs, progress, …) lives in the `run` hook
  // hoisted to Home so it survives navigating away mid-parse.
  const { runningHostId, runningArtifacts, runs } = run;
  const hasActiveRuns = runs.some((entry) => entry.status === "queued" || entry.status === "running");
  const runsByHost = useMemo(() => new Map(hosts.map((host) => [host.id, activeRunForHost(runs, host.id)])), [hosts, runs]);
  const terminalRunsByHost = useMemo(() => new Map(hosts.map((host) => [host.id, terminalRunForHost(runs, host.id)])), [hosts, runs]);

  useEffect(() => {
    let cancelled = false;
    setArtifactLoading(true);
    setArtifactError(null);
    window.api.listArtifacts().then((names) => {
      if (cancelled) return;
      setArtifacts(names);
      setSelectedArtifacts(new Set(names));
      setArtifactLoading(false);
    }).catch((error) => {
      if (!cancelled) {
        setArtifactError(errorMessage(error, "아티팩트 목록을 불러오지 못했습니다."));
        setArtifactLoading(false);
      }
    });
    return () => { cancelled = true; };
  }, [artifactLoadAttempt]);

  const filteredHosts = hosts.filter((host) => {
    const query = hostQuery.trim().toLocaleLowerCase();
    return !query || host.name.toLocaleLowerCase().includes(query) || host.targetDir.toLocaleLowerCase().includes(query);
  });
  const pageCount = Math.max(1, Math.ceil(filteredHosts.length / HOSTS_PER_PAGE));
  const pageStart = hostPage * HOSTS_PER_PAGE;
  const visibleHosts = filteredHosts.slice(pageStart, pageStart + HOSTS_PER_PAGE);
  const visibleHostRunStamp = visibleHosts.map((host) => {
    const active = activeRunForHost(runs, host.id);
    return `${host.id}:${host.lastRunAt ?? ""}:${active?.runId ?? ""}`;
  }).join("|");

  useEffect(() => {
    setHostPage((page) => Math.min(page, pageCount - 1));
  }, [pageCount]);

  useEffect(() => {
    let cancelled = false;
    // The small immutable manifest, not the historical host status alone,
    // tells us whether this exact run made a coherent result visible. A host
    // may start a new run while an old-manifest request is in flight; cache
    // each response against the host's persisted terminal timestamp so that
    // old unpublished state cannot survive the next terminal refresh.
    // Do not read the prior terminal manifest while this host has a queued or
    // running worker. Its old publication flag is not evidence about the
    // current attempt and would be cached before the terminal host refresh.
    const reportHosts = visibleHosts.filter((host) => !!host.lastRunAt && !activeRunForHost(runs, host.id));
    const stale = reportHosts.filter((host) => shouldLoadHostReport(
      reportsByHost[host.id],
      host.lastRunAt,
      Boolean(activeRunForHost(runs, host.id)),
      reportsByHost[host.id]?.report?.runId,
      terminalRunForHost(runs, host.id)?.runId,
    ));
    if (!stale.length) return () => { cancelled = true; };
    void Promise.all(stale.map(async (host) => {
      let report: ParseReport | null = null;
      try {
        report = await window.api.parseReport(host.dir);
      } catch {
        // A legacy/unreadable manifest is distinct from a parse failure. Keep
        // the host lifecycle state, but mark this exact timestamp as fetched.
      }
      return [host.id, { hostRunAt: host.lastRunAt!, report }] as const;
    }))
      .then((entries) => {
        if (cancelled) return;
        setReportsByHost((previous) => ({ ...previous, ...Object.fromEntries(entries) }));
      })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [reportsByHost, runs, visibleHostRunStamp]);

  async function pickTarget() {
    setFormError(null);
    try {
      const dir = await window.api.pickFolder();
      if (!dir) return;
      setNewHostTarget(dir);
      const suggestedName = folderName(dir);
      if (suggestedName) setNewHostName(suggestedName);
    } catch (error) {
      setFormError(errorMessage(error, "수집 데이터 폴더를 선택하지 못했습니다."));
    }
  }

  async function handleAddHost() {
    if (!newHostName.trim() || !newHostTarget) return;
    setCreating(true);
    setFormError(null);
    try {
      await window.api.createHost(activeCase.id, newHostName.trim(), newHostTarget);
      setNewHostName("");
      setNewHostTarget(null);
      onChanged();
    } catch (error) {
      setFormError(errorMessage(error, "호스트를 등록하지 못했습니다."));
    } finally {
      setCreating(false);
    }
  }

  function toggleArtifact(name: string) {
    setSelectedArtifacts((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  function handleRun(hostId: string) {
    const host = hosts.find((h) => h.id === hostId);
    const only = selectedArtifacts.size === artifacts.length ? undefined : Array.from(selectedArtifacts);
    setReportsByHost((previous) => {
      const next = { ...previous };
      delete next[hostId];
      return next;
    });
    // run.start awaits the child process and refreshes the case list (Home's
    // onDone) on completion — so the host list here updates without onChanged.
    run.start({ caseId: activeCase.id, hostId, hostName: host?.name ?? "", only, totalArtifacts: artifacts.length });
  }

  function handleRetryMft(hostId: string) {
    const host = hosts.find((item) => item.id === hostId);
    if (!host) return;
    setReportsByHost((previous) => {
      const next = { ...previous };
      delete next[hostId];
      return next;
    });
    run.start({
      caseId: activeCase.id,
      hostId,
      hostName: host.name,
      only: ["MFT"],
      totalArtifacts: 1,
    });
  }

  function handleCancel() {
    // This is the sole whole-queue cancellation path.  It derives from the
    // hoisted run state, so returning to this screen cannot lose the control.
    if (hasActiveRuns) void window.api.cancelPipeline(undefined, true);
  }

  function handleCancelRun(runId: string) {
    void run.cancel(runId);
  }

  function openRename(host: Host) {
    setRenameHost(host);
    setRenameName(host.name);
    setRenameError(null);
  }

  async function handleRenameHost() {
    if (!renameHost) return;
    const nextName = renameName.trim();
    if (!nextName) {
      setRenameError("호스트 이름을 입력하세요.");
      return;
    }
    if (hosts.some((host) => host.id !== renameHost.id && host.name.localeCompare(nextName, undefined, { sensitivity: "accent" }) === 0)) {
      setRenameError("같은 이름의 호스트가 이미 등록되어 있습니다.");
      return;
    }
    setRenaming(true);
    setRenameError(null);
    try {
      await window.api.renameHost(activeCase.id, renameHost.id, nextName);
      setRenameHost(null);
      onChanged();
    } catch (error) {
      setRenameError(errorMessage(error, "호스트 이름을 변경하지 못했습니다."));
    } finally {
      setRenaming(false);
    }
  }

  // Submit all runs. The backend owns the max-2 scheduling and the immutable
  // run ids, so this component cannot advance a hidden local queue on unmount.
  async function handleRunAll() {
    const only = selectedArtifacts.size === artifacts.length ? undefined : Array.from(selectedArtifacts);
    await Promise.all(hosts.map((h) => run.start({
      caseId: activeCase.id,
      hostId: h.id,
      hostName: h.name,
      only,
      totalArtifacts: artifacts.length,
    })));
  }

  async function handleDelete(hostId: string) {
    setDeleting(true);
    setActionError(null);
    try {
      await window.api.deleteHost(activeCase.id, hostId);
      onChanged();
    } catch (error) {
      setActionError(errorMessage(error, "호스트를 삭제하지 못했습니다."));
    } finally {
      setDeleting(false);
      setConfirmDeleteId(null);
    }
  }

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "18px 20px", gap: 12, overflow: "hidden", width: "100%" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 9, minHeight: 30, flexShrink: 0 }}>
        <strong className="dfir-page-title" style={{ fontSize: 17 }}>호스트 등록</strong>
    <span style={{ color: "var(--text-faint)", fontSize: 12 }}>등록된 호스트의 증거 원본과 파싱 상태를 관리합니다.</span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4, marginLeft: "auto", color: "var(--text-dim)", fontSize: 12 }}><DnsOutlinedIcon sx={{ fontSize: 16 }} />{hosts.length.toLocaleString()}개 등록됨</span>
      </header>

      {/* add host */}
      <section className="dfir-surface" aria-labelledby="add-host-title" style={{ padding: "13px 14px", flexShrink: 0 }}>
        <h2 id="add-host-title" style={{ margin: "0 0 10px", fontSize: 13.5 }}>새 호스트 추가</h2>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <input
            aria-label="호스트 이름"
            placeholder="호스트 이름 (예: WEB-01)"
            value={newHostName}
            onChange={(e) => setNewHostName(e.target.value)}
            style={{ padding: "7px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", minWidth: 180 }}
          />
          <button type="button" className="nm-btn" onClick={pickTarget} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 5, padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer" }}>
            <FolderOpenOutlinedIcon sx={{ fontSize: 16 }} />수집 데이터 폴더
          </button>
          <span style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={newHostTarget ?? ""}>
            {newHostTarget ?? "선택 안 됨"}
          </span>
          <button className="nm-btn"
            type="button"
            onClick={handleAddHost}
            disabled={creating || !newHostName.trim() || !newHostTarget}
            style={{ ...primaryButtonStyle, marginLeft: "auto", opacity: creating || !newHostName.trim() || !newHostTarget ? 0.5 : 1 }}
          >
            <AddIcon sx={{ fontSize: 16 }} />호스트 추가
          </button>
        </div>
        {formError && <div role="alert" style={{ marginTop: 9, color: "var(--danger)", fontSize: 12 }}>{formError}</div>}
      </section>

      {/* artifact selection */}
      <section className="dfir-surface" aria-labelledby="artifact-select-title" style={{ padding: "12px 14px", flexShrink: 0 }}>
        <div style={{ fontSize: 13, display: "flex", alignItems: "center" }}>
          <span id="artifact-select-title" style={{ fontWeight: 700 }}>실행할 아티팩트</span>
          {!artifactLoading && <span className="dfir-tag" style={{ marginLeft: 4, display: "inline-flex", alignItems: "center", gap: 4 }}><MemoryOutlinedIcon sx={{ fontSize: 14 }} />{selectedArtifacts.size}/{artifacts.length}</span>}
          {artifactLoading ? <span role="status" style={{ display: "inline-flex", alignItems: "center", gap: 6, marginLeft: 8, color: "var(--text-faint)", fontSize: 11.5 }}><CircularProgress size={13} thickness={5} />아티팩트 목록 확인 중</span> : <button type="button" onClick={() => setArtifactControlsExpanded((expanded) => !expanded)} aria-expanded={artifactControlsExpanded} aria-controls="artifact-selection-options" style={{ ...linkButtonStyle, marginLeft: "auto" }}>{artifactControlsExpanded ? <ExpandLessIcon sx={{ fontSize: 15 }} /> : <ExpandMoreIcon sx={{ fontSize: 15 }} />}{artifactControlsExpanded ? "접기" : "선택 변경"}</button>}
        </div>
        {artifactControlsExpanded && artifacts.length > 0 && <>
          <div style={{ fontSize: 13, marginTop: 10, marginBottom: 10, display: "flex", alignItems: "center" }}>
            <button type="button" className="nm-btn" onClick={() => setSelectedArtifacts(new Set(artifacts))} disabled={hasActiveRuns} style={{ ...linkButtonStyle, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: "3px 9px", justifyContent: "center", opacity: hasActiveRuns ? 0.5 : 1 }}><SelectAllIcon sx={{ fontSize: 14 }} />전체 선택</button>
            <button type="button" className="nm-btn" onClick={() => setSelectedArtifacts(new Set())} disabled={hasActiveRuns} style={{ ...linkButtonStyle, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: "3px 9px", justifyContent: "center", opacity: hasActiveRuns ? 0.5 : 1 }}><DeselectIcon sx={{ fontSize: 14 }} />전체 해제</button>
          </div>
          <div id="artifact-selection-options" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))", gap: 8, maxHeight: 260, overflow: "auto", paddingRight: 4 }}>{artifacts.map((name) => {
            const isCurrent = runningArtifacts.includes(name);
            const checked = selectedArtifacts.has(name);
            return <button key={name} type="button" aria-pressed={checked} onClick={() => toggleArtifact(name)} disabled={hasActiveRuns} style={{ display: "flex", alignItems: "center", justifyContent: "center", minWidth: 0, padding: "7px 12px", border: `1px solid ${isCurrent || checked ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border-subtle)"}`, borderRadius: "var(--radius-md)", fontSize: 12.5, cursor: hasActiveRuns ? "default" : "pointer", background: isCurrent ? "color-mix(in srgb, var(--accent) 20%, var(--bg-elevated))" : checked ? "var(--accent-subtle)" : "color-mix(in srgb, var(--bg-input) 72%, var(--bg))", color: checked ? "var(--accent)" : "var(--text-faint)", fontWeight: checked ? 650 : 500, textAlign: "center", opacity: hasActiveRuns && !isCurrent ? .62 : 1 }}>{name}</button>;
          })}</div>
        </>}
        {!artifactLoading && !artifactError && artifacts.length === 0 && <div role="status" style={{ marginTop: 8, color: "var(--warning)", fontSize: 12 }}>실행 가능한 아티팩트가 없습니다. 파싱을 시작할 수 없습니다.</div>}
        {artifactError && <div role="alert" style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 9, color: "var(--danger)", fontSize: 12 }}>{artifactError}<button type="button" onClick={() => setArtifactLoadAttempt((attempt) => attempt + 1)} style={{ ...linkButtonStyle, marginLeft: 0 }}>다시 시도</button></div>}
      </section>

      {/* Host ledger is intentionally the only independently scrolling region. */}
      <section aria-labelledby="host-ledger-title" style={{ flex: "1 1 0", minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", containerType: "inline-size" }}>
        <div className="host-ledger-toolbar" style={{ display: "flex", alignItems: "center", gap: 9, padding: "10px 2px", flexShrink: 0 }}>
          <h2 id="host-ledger-title" style={{ margin: 0, fontSize: 13.5 }}>등록 호스트</h2>
          <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{filteredHosts.length.toLocaleString()}개 표시</span>
          {runs.some((entry) => entry.status === "queued" || entry.status === "running") && <span aria-live="polite" style={{ display: "inline-flex", alignItems: "center", gap: 5, color: "var(--text-dim)", fontSize: 11.5, whiteSpace: "nowrap" }}><CircularProgress size={13} thickness={5} />{runs.filter((entry) => entry.status === "running").length}개 실행 · {runs.filter((entry) => entry.status === "queued").length}개 대기</span>}
          <input className="host-ledger-search" aria-label="호스트 또는 증거 경로 검색" value={hostQuery} onChange={(event) => { setHostQuery(event.target.value); setHostPage(0); }} placeholder="호스트·증거 경로 검색" style={{ width: 230, marginLeft: "auto", padding: "6px 9px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12 }} />
          {hasActiveRuns ? <button className="nm-btn" type="button" onClick={handleCancel} style={{ ...dangerButtonStyle, padding: "5px 10px", fontSize: 12 }}><CancelOutlinedIcon sx={{ fontSize: 15 }} />전체 실행·대기 항목 중지</button> : hosts.length > 1 && <button className="nm-btn" type="button" onClick={handleRunAll} disabled={selectedArtifacts.size === 0} style={{ ...primaryButtonStyle, padding: "5px 10px", fontSize: 12, opacity: selectedArtifacts.size === 0 ? 0.5 : 1 }}><PlayArrowIcon sx={{ fontSize: 15 }} />전체 파싱</button>}
        </div>
        {actionError && <div role="alert" style={{ margin: "0 0 8px", padding: "8px 12px", border: "1px solid color-mix(in srgb, var(--danger) 45%, var(--border))", borderRadius: "var(--radius-md)", background: "color-mix(in srgb, var(--danger) 7%, var(--bg-panel))", color: "var(--danger)", fontSize: 12 }}>{actionError}</div>}
        <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "2px 2px 4px" }}>
          <div>
            {hosts.length === 0 && <div role="status" style={{ padding: 28, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>등록된 호스트가 없습니다. 위에서 증거 폴더를 선택해 추가하세요.</div>}
            {hosts.length > 0 && visibleHosts.length === 0 && <div role="status" style={{ padding: 28, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>검색 조건과 일치하는 호스트가 없습니다.</div>}
            {visibleHosts.map((host) => {
              const activeRun = runsByHost.get(host.id);
              const terminalRun = terminalRunsByHost.get(host.id);
              const cached = reportsByHost[host.id];
              const report = selectVisibleHostReport(cached, host.lastRunAt, Boolean(activeRun), terminalRun?.runId);
              const reportSyncPending = isHostReportSyncPending(cached, host.lastRunAt, Boolean(activeRun), terminalRun?.runId);
              return <HostLedgerRow key={host.id} host={host} report={report} reportSyncPending={reportSyncPending} activeRun={activeRun} terminalRun={terminalRun} hasActiveRuns={hasActiveRuns} selectedArtifacts={selectedArtifacts.size} confirmDeleteId={confirmDeleteId} deleting={deleting} onRun={handleRun} onRetryMft={handleRetryMft} onCancel={handleCancelRun} onOpenHost={onOpenHost} onConfirmDelete={setConfirmDeleteId} onDelete={handleDelete} onRename={openRename} />;
            })}
          </div>
        </div>
        {filteredHosts.length > HOSTS_PER_PAGE && <div style={{ display: "flex", justifyContent: "flex-end", padding: "8px 2px", flexShrink: 0 }}><PaginationControls ariaLabel="호스트 목록 페이지" page={hostPage} pageCount={pageCount} onChange={setHostPage} summary={`(${(pageStart + 1).toLocaleString()}–${Math.min(pageStart + HOSTS_PER_PAGE, filteredHosts.length).toLocaleString()} / ${filteredHosts.length.toLocaleString()})`} /></div>}
      </section>
      {renameHost && <RenameHostDialog value={renameName} saving={renaming} error={renameError} onChange={setRenameName} onClose={() => { if (!renaming) setRenameHost(null); }} onSave={() => void handleRenameHost()} />}
    </div>
  );
}

function HostLedgerRow({
  host, report, reportSyncPending, activeRun, terminalRun, hasActiveRuns, selectedArtifacts, confirmDeleteId, deleting,
  onRun, onRetryMft, onCancel, onOpenHost, onConfirmDelete, onDelete, onRename,
}: {
  host: Host;
  report?: ParseReport | null;
  reportSyncPending: boolean;
  activeRun?: PipelineRunItem;
  /** Last in-session terminal update fills the small refresh gap only. */
  terminalRun?: PipelineRunItem;
  hasActiveRuns: boolean;
  selectedArtifacts: number;
  confirmDeleteId: string | null;
  deleting: boolean;
  onRun: (hostId: string) => void;
  onRetryMft: (hostId: string) => void;
  onCancel: (runId: string) => void;
  onOpenHost: (host: Host) => void;
  onConfirmDelete: (hostId: string | null) => void;
  onDelete: (hostId: string) => void;
  onRename: (host: Host) => void;
}) {
  // A partial/error attempt may preserve earlier files, but it must not offer
  // an unqualified "결과" action as if this attempt published a coherent view.
  const hasResult = report?.status === "ok" && (report.published === true || report.published === undefined);
  const hasPublishedRaw = report?.status === "partial" && report.published === true && (report.publishedOutputs?.length ?? 0) > 0;
  // 정상 완료든, 손상 아티팩트를 건너뛴 부분 완료든 열람 동작은 같다 —
  // 버튼은 "결과 보기" 하나로 통일한다.
  // 방금 이 세션에서 정상 완료한 실행은 발행까지 끝난 상태다 — 보고서
  // 재동기화를 기다리지 않고 즉시 결과를 열 수 있게 한다.
  const canOpenResult = hasResult || hasPublishedRaw || terminalRun?.status === "complete";
  const isQueued = activeRun?.status === "queued";
  const confirmingDelete = confirmDeleteId === host.id;
  const terminalStatus = terminalRun?.status === "complete" ? "ok" : terminalRun?.status;
  const displayStatus = activeRun?.status ?? terminalStatus ?? host.lastRunStatus;
  const progressLabel = isQueued
    ? "대기 중"
    : activeRun?.currentArtifact === "_OVERVIEW"
      ? "종합 분석 생성 중…"
      : activeRun?.currentArtifact === "파일 확인"
        ? "원본 파일 확인 중…"
        : activeRun?.currentArtifact ? `${activeRun.currentArtifact} 파싱 중…` : "준비 중…";
  const percent = !activeRun || isQueued || activeRun.totalSteps <= 0
    ? 0
    : Math.min(99, Math.round((activeRun.completedSteps / activeRun.totalSteps) * 100));
  // 카드 타일 색 = 실행 상태 신호.
  const tileColor = activeRun ? "var(--accent)" : displayStatus === "ok" ? "var(--success)" : displayStatus === "error" ? "var(--danger)" : displayStatus ? "var(--warning)" : "var(--text-dim)";
  return <article style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 8, padding: "11px 14px", border: `1px solid ${activeRun ? "color-mix(in srgb, var(--accent) 45%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: activeRun ? "color-mix(in srgb, var(--accent) 5%, var(--bg-panel))" : "var(--bg-panel)", transition: "border-color .18s ease" }}>
    <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", alignItems: "stretch", gap: 6 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
      <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${tileColor} 15%, transparent)` }}>
        <DnsOutlinedIcon sx={{ fontSize: 17, color: tileColor }} />
      </span>
      <div style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <strong style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 13.5 }}>{host.name}</strong>
          <StatusPill status={displayStatus ?? null} />
        </div>
        <span title={host.targetDir} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{host.targetDir}</span>
      </div>
      <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
        {host.lastRunAt ? (
          reportSyncPending && <span role="status" aria-live="polite" style={{ display: "inline-flex", alignItems: "center", gap: 5, color: "var(--text-faint)" }}><CircularProgress size={12} thickness={5} aria-hidden="true" />이번 실행 보고서 동기화 중</span>
        ) : terminalStatus ? <span style={{ color: "var(--text-faint)" }}>방금 {terminalStatusLabel(terminalStatus)} · 저장 정보 갱신 중</span> : <span style={{ color: "var(--text-faint)" }}>실행 기록 없음</span>}
      </div>
    </div>
    {/* A host-level fallback status can belong to the previous run. Do not
        surface it until the exact terminal manifest has passed the same
        cache/run-id gate as the publication controls above. */}
    {report && !activeRun && !reportSyncPending && <RunOutcomeSummary host={host} report={report} onRetryMft={() => onRetryMft(host.id)} />}
    {activeRun && !isQueued && <div style={{ gridColumn: "1 / -1" }}><InlineParseProgress stepLabel={progressLabel} percent={percent} completedSteps={activeRun.completedSteps} totalSteps={activeRun.totalSteps} /></div>}
    {activeRun?.failedArtifacts.length ? <div role="alert" style={{ gridColumn: "1 / -1", padding: "0 0 6px", color: "var(--danger)", fontSize: 12 }}>파싱 실패: {activeRun.failedArtifacts.join(", ")}</div> : null}
    </div>
    {confirmingDelete ? <div className="host-ledger-confirm"><span style={{ color: "var(--danger)", fontSize: 11.5 }}>분석 결과와 이 호스트 북마크를 삭제합니다.</span><div style={{ display: "flex", gap: 7 }}><button className="nm-btn" type="button" onClick={() => onDelete(host.id)} disabled={deleting} style={{ ...dangerButtonStyle, padding: "5px 9px", fontSize: 11.5, opacity: deleting ? .5 : 1 }}><DeleteOutlineIcon sx={{ fontSize: 14 }} />삭제</button><button type="button" onClick={() => onConfirmDelete(null)} disabled={deleting} style={{ ...linkButtonStyle, marginLeft: 0 }}>취소</button></div></div> : <div className="host-ledger-actions">
        {canOpenResult ? <button className="nm-btn" type="button" onClick={() => onOpenHost(host)} style={{ ...neutralButtonStyle, padding: "8px 14px", fontSize: 12.5 }}><VisibilityOutlinedIcon sx={{ fontSize: 16 }} />결과 보기</button> : <span aria-hidden="true" className="host-ledger-action-placeholder" />}
        {activeRun ? <button className="nm-btn" type="button" onClick={() => onCancel(activeRun.runId)} style={{ ...dangerButtonStyle, padding: "8px 14px", fontSize: 12.5 }}><CancelOutlinedIcon sx={{ fontSize: 16 }} />{isQueued ? "대기 취소" : "취소"}</button> : <button className="nm-btn" type="button" onClick={() => onRun(host.id)} disabled={hasActiveRuns || selectedArtifacts === 0} style={{ ...primaryButtonStyle, padding: "8px 14px", fontSize: 12.5, opacity: hasActiveRuns || selectedArtifacts === 0 ? .5 : 1 }}><PlayArrowIcon sx={{ fontSize: 16 }} />파싱</button>}
        <span aria-hidden="true" className="host-ledger-action-divider" />
        <button type="button" onClick={() => onRename(host)} disabled={!!activeRun} aria-label={`${host.name} 이름 변경`} title="호스트 표시 이름 변경" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, padding: 0, background: "transparent", color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", cursor: activeRun ? "default" : "pointer", opacity: activeRun ? .4 : 1 }}><EditOutlinedIcon sx={{ fontSize: 18 }} /></button>
        <button type="button" onClick={() => onConfirmDelete(host.id)} disabled={!!activeRun} aria-label={`${host.name} 삭제`} title="호스트 삭제 (원본 수집 데이터는 유지)" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, padding: 0, background: "transparent", color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", cursor: activeRun ? "default" : "pointer", opacity: activeRun ? .4 : 1 }}><DeleteOutlineIcon sx={{ fontSize: 18 }} /></button>
      </div>}
  </article>;
}
