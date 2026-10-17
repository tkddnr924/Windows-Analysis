"use client";
import PaginationControls from "@/components/PaginationControls";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import AddIcon from "@mui/icons-material/Add";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutlineOutlined";
import RestartAltIcon from "@mui/icons-material/RestartAlt";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutlineOutlined";
import EditOutlinedIcon from "@mui/icons-material/EditOutlined";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import OpenInNewOutlinedIcon from "@mui/icons-material/OpenInNewOutlined";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import TaskAltIcon from "@mui/icons-material/TaskAlt";
import TimerOutlinedIcon from "@mui/icons-material/TimerOutlined";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import { FaWindows } from "react-icons/fa";
import CircularProgress from "@mui/material/CircularProgress";
import type { Case, Host, ParseReport } from "@/lib/types";
import { isHostReportSyncPending, selectVisibleHostReport, shouldLoadHostReport, type HostReportCacheEntry } from "@/lib/hostReportCache";
import { allParseBlocked, canStartParse, parseBlockedLabel, type ParseEligibilityEntry } from "@/lib/parseEligibility";
import { type PipelineRun, type PipelineRunItem } from "@/lib/usePipelineRun";
import { hostProgress, type ProgressBar } from "@/lib/pipelineProgress";
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
  borderRadius: "var(--radius)",
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
  borderRadius: "var(--radius)",
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
  borderRadius: "var(--radius)",
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
    return <span style={statusPillStyle("var(--accent)")}><CircularProgress size={11} thickness={5} />실행 중</span>;
  if (status === "queued")
    return <span style={statusPillStyle("var(--text-dim)")}><TimerOutlinedIcon sx={{ fontSize: 13 }} />대기 중</span>;
  if (status === "ok" || status === "complete")
    return <span style={statusPillStyle("var(--success)")}><TaskAltIcon sx={{ fontSize: 13 }} />완료</span>;
  if (status === "error")
    return <span style={statusPillStyle("var(--danger)")}><ErrorOutlineIcon sx={{ fontSize: 13 }} />오류</span>;
  if (status === "partial")
    return <span style={statusPillStyle("var(--warning)")}><ErrorOutlineIcon sx={{ fontSize: 13 }} />부분 완료</span>;
  if (status === "cancelled")
    return <span style={statusPillStyle("var(--text-dim)")}><CancelOutlinedIcon sx={{ fontSize: 13 }} />취소됨</span>;
  return <span style={statusPillStyle("var(--text-faint)")}><TimerOutlinedIcon sx={{ fontSize: 13 }} />미실행</span>;
}

function statusPillStyle(color: string): React.CSSProperties {
  // 라벨은 아웃라인 스타일 — 채움 배경 대신 색 테두리 + 투명 배경.
  return { display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 4, fontSize: 11, fontWeight: 600, color, background: "transparent", border: `1px solid color-mix(in srgb, ${color} 55%, transparent)`, padding: "2px 8px", borderRadius: "var(--radius)", textAlign: "center" };
}

function folderName(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, "");
  return trimmed.split(/[\\/]/).pop() ?? "";
}

function InlineParseProgress({ bar }: { bar: ProgressBar }) {
  const color = bar.active ? "var(--accent)" : "var(--text-dim)";
  const label = bar.label.replace(/…$/, "");
  return (
    <div style={{ padding: "4px 0 8px", display: "flex", flexDirection: "column", gap: 7 }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color }}>
          {label}{bar.active && <span className="parse-progress__dots" aria-label="진행 중">...</span>}
        </span>
        <span style={{ fontSize: 20, fontWeight: 700, fontVariantNumeric: "tabular-nums", color }}>{bar.percent}%</span>
      </div>
      <div className="parse-progress__track">
        <div className="parse-progress__fill" style={{ width: `${bar.percent}%`, background: color }} />
      </div>
      <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{bar.detail}</span>
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

function terminalRunForHost(runs: PipelineRunItem[], hostId: string, forgotten: ReadonlySet<string>): PipelineRunItem | undefined {
  return [...runs].reverse().find((run) => run.hostId === hostId && !forgotten.has(run.runId)
    && (run.status === "complete" || run.status === "partial" || run.status === "error" || run.status === "cancelled"));
}

function terminalStatusLabel(status: string): string {
  if (status === "ok" || status === "complete") return "완료";
  if (status === "partial") return "부분 완료";
  if (status === "error") return "오류";
  return "취소";
}

/** Mounted only while the stored log panel is open. */
function RunLogDetail({ host, report }: { host: Host; report: ParseReport }) {
  const [text, setText] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const runId = report.runId;
  // Latest requested run id; stale responses for an older run are dropped.
  const runIdRef = useRef(runId);
  runIdRef.current = runId;

  async function load() {
    if (!runId) return;
    const requested = runId;
    setLoaded(false);
    setError(null);
    setText(null);
    try {
      const preview = await window.api.parseRunLog(host.dir, requested);
      if (runIdRef.current !== requested) return;
      setText(preview.text);
      setTruncated(preview.truncated);
      setLoaded(true);
    } catch (cause) {
      if (runIdRef.current !== requested) return;
      setError(errorMessage(cause, "실행 로그를 불러오지 못했습니다."));
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  if (!runId) return null;

  async function openLogFile() {
    setOpening(true);
    setOpenError(null);
    try {
      await window.api.openParseRunLog(host.dir, runId!);
    } catch (cause) {
      setOpenError(errorMessage(cause, "로그 파일을 열지 못했습니다."));
    } finally {
      setOpening(false);
    }
  }

  return <div style={{ display: "grid", gap: 5, marginTop: 2 }}>
    {!loaded && !error && <span role="status" style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-faint)" }}><CircularProgress size={12} thickness={5} aria-hidden="true" />로그를 불러오는 중…</span>}
    {error && <span role="alert" style={{ color: "var(--danger)" }}>{error} <button type="button" onClick={() => void load()} style={linkButtonStyle}>다시 시도</button></span>}
    {loaded && <pre aria-label={`${host.name} 실행 로그 내용`} style={{ maxHeight: 168, overflow: "auto", margin: 0, padding: "8px 10px", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{text || "기록된 로그 행이 없습니다."}{truncated ? "\n\n… 앞부분 24KB만 표시합니다." : ""}</pre>}
    <button className="nm-btn" type="button" onClick={() => void openLogFile()} disabled={opening} aria-label={`${host.name} 실행 로그 파일 열기`} style={{ ...neutralButtonStyle, width: "fit-content", padding: "4px 10px", fontSize: 11.5, opacity: opening ? .5 : 1 }}><OpenInNewOutlinedIcon sx={{ fontSize: 15 }} />로그보기</button>
    {openError && <span role="alert" style={{ color: "var(--danger)" }}>{openError}</span>}
  </div>;
}

function RunLogPanel({ id, host, report, onRetryMft }: { id: string; host: Host; report: ParseReport; onRetryMft?: () => void }) {
  const terminalStatus = report.status ?? host.lastRunStatus;
  const summaryColor = terminalStatus === "error"
    ? "var(--danger)"
    : terminalStatus === "partial"
      ? "var(--warning)"
      : terminalStatus === "cancelled" ? "var(--text-dim)" : "var(--success)";
  const mft = report.artifacts.find((artifact) => artifact.name === "MFT");
  const retryMft = report.status === "partial" && report.artifacts.some((artifact) => artifact.name === "MFT" && artifact.status === "failed");
  // 오류 원문은 여기 요약하지 않는다 — 세부 내용은 아래 실행 로그 본문으로 본다.
  return <div id={id} style={{ display: "grid", gap: 6, marginTop: 2, padding: "10px 12px", color: "var(--text-dim)", border: "1px solid var(--border)", borderLeft: `3px solid ${summaryColor}`, borderRadius: "var(--radius)", background: "var(--bg)", fontSize: 12 }}>
    <span style={{ color: "var(--text-faint)" }}>총 소요 {formatDuration(host.lastRunDurationSecs ?? 0)}</span>
    {mft?.status === "no_input" && <span>MFT: 원본 $MFT 파일 미수집 · 이번 실행에서는 결과를 만들지 않았습니다.</span>}
    {mft?.status === "failed" && <span>MFT: 파싱 실패 · MFT 결과는 공개되지 않았습니다.</span>}
    <RunLogDetail host={host} report={report} />
    {retryMft && onRetryMft && <button className="nm-btn" type="button" onClick={onRetryMft} style={{ ...neutralButtonStyle, width: "fit-content", padding: "4px 10px", fontSize: 11.5 }}>MFT만 재시도</button>}
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
        <input data-dialog-autofocus value={value} onChange={(event) => onChange(event.target.value)} disabled={saving} style={{ padding: "8px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text)" }} />
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

function DeleteHostDialog({
  host,
  deleting,
  error,
  onClose,
  onConfirm,
}: {
  host: Host;
  deleting: boolean;
  error: string | null;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useModalDialog(onClose);
  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1400, display: "grid", placeItems: "center", padding: 18, background: "rgba(0, 0, 0, 0.46)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descriptionId} tabIndex={-1} onClick={(event) => event.stopPropagation()} className="dfir-surface" style={{ width: "min(420px, 100%)", padding: 18 }}>
      <h2 id={titleId} style={{ margin: "0 0 6px", fontSize: 15 }}>정말 삭제하시겠습니까?</h2>
      <p id={descriptionId} style={{ margin: "0 0 14px", color: "var(--text-dim)", fontSize: 12.5 }}>{host.name}의 분석 결과와 이 호스트 북마크를 삭제합니다. 원본 수집 데이터는 그대로 둡니다.</p>
      {error && <div role="alert" style={{ margin: "0 0 9px", color: "var(--danger)", fontSize: 12 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        {/* 파괴적 동작이므로 최초 포커스는 취소에 둔다 — Enter 오입력이 삭제가 되지 않게. */}
        <button data-dialog-autofocus className="nm-btn" type="button" onClick={onClose} disabled={deleting} style={{ ...neutralButtonStyle, opacity: deleting ? .5 : 1 }}>취소</button>
        <button className="nm-btn" type="button" onClick={onConfirm} disabled={deleting} style={{ ...dangerButtonStyle, opacity: deleting ? .5 : 1 }}><DeleteOutlineIcon sx={{ fontSize: 16 }} />{deleting ? "삭제 중" : "삭제"}</button>
      </div>
    </div>
  </div>;
}

function ResetHostsDialog({ count, resetting, error, onClose, onConfirm }: {
  count: number;
  resetting: boolean;
  error: string | null;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useModalDialog(onClose);
  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1400, display: "grid", placeItems: "center", padding: 18, background: "rgba(0, 0, 0, 0.46)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descriptionId} tabIndex={-1} onClick={(event) => event.stopPropagation()} className="dfir-surface" style={{ width: "min(420px, 100%)", padding: 18 }}>
      <h2 id={titleId} style={{ margin: "0 0 6px", fontSize: 15 }}>파싱 전 상태로 초기화할까요?</h2>
      <p id={descriptionId} style={{ margin: "0 0 14px", color: "var(--text-dim)", fontSize: 12.5 }}>등록 호스트 {count.toLocaleString()}개의 분석 결과·파싱 로그·북마크를 삭제합니다. 호스트 등록(이름·증거 경로)과 원본 수집 데이터는 그대로 둡니다.</p>
      {error && <div role="alert" style={{ margin: "0 0 9px", color: "var(--danger)", fontSize: 12 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 16 }}>
        {/* Destructive: initial focus stays on cancel. */}
        <button data-dialog-autofocus className="nm-btn" type="button" onClick={onClose} disabled={resetting} style={{ ...neutralButtonStyle, opacity: resetting ? .5 : 1 }}>취소</button>
        <button className="nm-btn" type="button" onClick={onConfirm} disabled={resetting} style={{ ...dangerButtonStyle, opacity: resetting ? .5 : 1 }}><RestartAltIcon sx={{ fontSize: 16 }} />{resetting ? "초기화 중" : "초기화"}</button>
      </div>
    </div>
  </div>;
}

/** Failed checks never grant permission to parse. */
async function checkHostEligibility(caseId: string, hostId: string): Promise<ParseEligibilityEntry> {
  try {
    const verdict = await window.api.hostParseEligibility(caseId, hostId);
    return { status: "ready", canParse: verdict.canParse, reason: verdict.reason };
  } catch (error) {
    return { status: "error", message: errorMessage(error, "새 데이터 여부를 확인하지 못했습니다.") };
  }
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
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const [eligibility, setEligibility] = useState<Record<string, ParseEligibilityEntry | undefined>>({});
  const [eligibilityAttempt, setEligibilityAttempt] = useState(0);
  const [runAllChecking, setRunAllChecking] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Host | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resetError, setResetError] = useState<string | null>(null);
  // Finished in-session runs whose results a reset removed.
  const [forgottenRuns, setForgottenRuns] = useState<ReadonlySet<string>>(new Set());
  const [actionError, setActionError] = useState<string | null>(null);
  const [hostQuery, setHostQuery] = useState("");
  const [hostPage, setHostPage] = useState(0);
  const [renameHost, setRenameHost] = useState<Host | null>(null);
  const [renameName, setRenameName] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [reportsByHost, setReportsByHost] = useState<Record<string, HostReportCacheEntry<ParseReport>>>({});

  // The parse state (logs, progress, queue, …) lives in the `run` hook hoisted
  // to Home so it survives navigating away mid-parse.
  const { runs } = run;
  const hasActiveRuns = runs.some((entry) => entry.status === "queued" || entry.status === "running");
  const runsByHost = useMemo(() => new Map(hosts.map((host) => [host.id, activeRunForHost(runs, host.id)])), [hosts, runs]);
  const terminalRunsByHost = useMemo(() => new Map(hosts.map((host) => [host.id, terminalRunForHost(runs, host.id, forgottenRuns)])), [hosts, runs, forgottenRuns]);

  useEffect(() => {
    let cancelled = false;
    setArtifactLoading(true);
    setArtifactError(null);
    window.api.listArtifacts().then((names) => {
      if (cancelled) return;
      setArtifacts(names);
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
      terminalRunForHost(runs, host.id, forgottenRuns)?.runId,
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
  }, [reportsByHost, runs, visibleHostRunStamp, forgottenRuns]);

  // Evidence may change while the window is inactive.
  useEffect(() => {
    const recheck = () => setEligibilityAttempt((attempt) => attempt + 1);
    const recheckIfVisible = () => { if (!document.hidden) recheck(); };
    window.addEventListener("focus", recheck);
    document.addEventListener("visibilitychange", recheckIfVisible);
    return () => {
      window.removeEventListener("focus", recheck);
      document.removeEventListener("visibilitychange", recheckIfVisible);
    };
  }, []);

  // Coalesce lifecycle/focus changes and discard stale verdicts.
  useEffect(() => {
    const hostIds = visibleHosts.map((host) => host.id);
    if (!hostIds.length) return;
    let cancelled = false;
    setEligibility((previous) => {
      const next = { ...previous };
      for (const hostId of hostIds) next[hostId] = { status: "checking" };
      return next;
    });
    const timer = window.setTimeout(() => {
      void Promise.all(hostIds.map(async (hostId) =>
        [hostId, await checkHostEligibility(activeCase.id, hostId)] as const
      )).then((entries) => {
        if (!cancelled) setEligibility((previous) => ({ ...previous, ...Object.fromEntries(entries) }));
      });
    }, 100);
    return () => { cancelled = true; window.clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCase.id, eligibilityAttempt, visibleHostRunStamp]);

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

  function handleRun(hostId: string) {
    const host = hosts.find((item) => item.id === hostId);
    // Full parsing requires a positive eligibility verdict.
    if (!host || hasActiveRuns || artifacts.length === 0 || !canStartParse(eligibility[hostId])) return;
    setReportsByHost((previous) => {
      const next = { ...previous };
      delete next[hostId];
      return next;
    });
    // run.start awaits the child process and refreshes the case list (Home's
    // onDone) on completion — so the host list here updates without onChanged.
    run.start({ caseId: activeCase.id, hostId, hostName: host.name, totalArtifacts: artifacts.length });
  }

  // Preserve the existing explicit MFT-only retry.
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
    // Whole-queue stop goes through the hook so each run is marked cancelled.
    for (const entry of runs) {
      if (entry.status === "queued" || entry.status === "running") void handleCancelRun(entry.runId);
    }
  }

  async function handleCancelRun(runId: string) {
    setActionError((await run.cancel(runId)) ? null : "파싱을 취소하지 못했습니다.");
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
  // Bulk parsing must not bypass individual eligibility.
  async function handleRunAll() {
    if (hasActiveRuns || artifacts.length === 0 || runAllChecking) return;
    setRunAllChecking(true);
    setActionError(null);
    const checked = await Promise.all(hosts.map(async (host) => [host.id, await checkHostEligibility(activeCase.id, host.id)] as const));
    setRunAllChecking(false);
    setEligibility((previous) => ({ ...previous, ...Object.fromEntries(checked) }));
    const startable = checked.filter(([, entry]) => canStartParse(entry)).map(([hostId]) => hostId);
    const unchecked = checked.filter(([, entry]) => entry.status === "error").length;
    if (!startable.length) {
      setActionError(unchecked
        ? `${unchecked.toLocaleString()}개 호스트의 새 데이터 여부를 확인하지 못해 전체 파싱을 시작하지 않았습니다.`
        : "새로 추가된 데이터가 있는 호스트가 없어 전체 파싱을 시작하지 않았습니다.");
      return;
    }
    if (unchecked) setActionError(`${unchecked.toLocaleString()}개 호스트는 새 데이터 여부를 확인하지 못해 제외했습니다.`);
    await Promise.all(startable.map((hostId) => run.start({
      caseId: activeCase.id,
      hostId,
      hostName: hosts.find((host) => host.id === hostId)?.name ?? "",
      totalArtifacts: artifacts.length,
    })));
  }

  function openDeleteConfirm(host: Host) {
    setActionError(null);
    setDeleteTarget(host);
  }

  async function handleDelete(hostId: string) {
    setDeleting(true);
    setActionError(null);
    try {
      await window.api.deleteHost(activeCase.id, hostId);
      setDeleteTarget(null);
      onChanged();
    } catch (error) {
      setActionError(errorMessage(error, "호스트를 삭제하지 못했습니다."));
    } finally {
      setDeleting(false);
    }
  }

  async function handleReset() {
    setResetting(true);
    setResetError(null);
    try {
      await window.api.resetHosts(activeCase.id);
      setResetOpen(false);
    } catch (error) {
      setResetError(errorMessage(error, "초기화하지 못했습니다."));
    } finally {
      // Partial failures still removed some results: refresh either way.
      setForgottenRuns(new Set(runs.map((entry) => entry.runId)));
      setEligibilityAttempt((attempt) => attempt + 1);
      onChanged();
      setResetting(false);
    }
  }

  // Artifact names provide the progress denominator, not a selection UI.
  const artifactsReady = !artifactLoading && !artifactError && artifacts.length > 0;
  const allParseDisabled = !artifactsReady || runAllChecking || allParseBlocked(hosts.map((host) => host.id), eligibility);
  const allParseHint = !artifactsReady
    ? "실행할 아티팩트 목록을 확인하지 못해 파싱을 시작할 수 없습니다."
    : runAllChecking
      ? "새 데이터 여부를 확인하는 중입니다."
      : undefined;

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "18px 20px", gap: 12, overflow: "hidden", width: "100%" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 9, minHeight: 30, flexShrink: 0 }}>
        <FaWindows size={17} style={{ color: "var(--accent)", flexShrink: 0 }} aria-hidden="true" />
        <strong className="dfir-page-title" style={{ fontSize: 17 }}>호스트 등록</strong>
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
            style={{ padding: "7px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text)", minWidth: 180 }}
          />
          <button type="button" className="nm-btn" onClick={pickTarget} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 5, padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer" }}>
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

      {/* Host ledger is intentionally the only independently scrolling region. */}
      <section aria-labelledby="host-ledger-title" style={{ flex: "1 1 0", minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", containerType: "inline-size" }}>
        <div className="host-ledger-toolbar" style={{ display: "flex", alignItems: "center", gap: 9, padding: "10px 2px", flexShrink: 0 }}>
          <h2 id="host-ledger-title" style={{ margin: 0, fontSize: 13.5 }}>등록 호스트</h2>
          <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{filteredHosts.length.toLocaleString()}개 표시</span>
          {runs.some((entry) => entry.status === "queued" || entry.status === "running") && <span aria-live="polite" style={{ display: "inline-flex", alignItems: "center", gap: 5, color: "var(--text-dim)", fontSize: 11.5, whiteSpace: "nowrap" }}><CircularProgress size={13} thickness={5} />{runs.filter((entry) => entry.status === "running").length}개 실행 · {runs.filter((entry) => entry.status === "queued").length}개 대기</span>}
          <input className="host-ledger-search" aria-label="호스트 또는 증거 경로 검색" value={hostQuery} onChange={(event) => { setHostQuery(event.target.value); setHostPage(0); }} placeholder="호스트·증거 경로 검색" style={{ width: 230, marginLeft: "auto", padding: "6px 9px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text)", fontSize: 12 }} />
          {!hasActiveRuns && hosts.length > 0 && <button className="nm-btn" type="button" onClick={() => { setResetError(null); setResetOpen(true); }} disabled={!hosts.some((host) => host.lastRunAt)} title="모든 호스트를 파싱 전 상태로 되돌림 (원본 수집 데이터는 유지)" style={{ ...neutralButtonStyle, padding: "5px 10px", fontSize: 12, color: "var(--danger)", opacity: hosts.some((host) => host.lastRunAt) ? 1 : 0.5 }}><RestartAltIcon sx={{ fontSize: 15 }} />초기화</button>}
          {hasActiveRuns ? <button className="nm-btn" type="button" onClick={handleCancel} style={{ ...dangerButtonStyle, padding: "5px 10px", fontSize: 12 }}><CancelOutlinedIcon sx={{ fontSize: 15 }} />전체 실행·대기 항목 중지</button> : hosts.length > 1 && <button className="nm-btn" type="button" onClick={() => void handleRunAll()} disabled={allParseDisabled} title={allParseHint} style={{ ...primaryButtonStyle, padding: "5px 10px", fontSize: 12, opacity: allParseDisabled ? 0.5 : 1 }}>{runAllChecking ? <CircularProgress size={13} thickness={5} aria-hidden="true" /> : <PlayArrowIcon sx={{ fontSize: 15 }} />}{runAllChecking ? "새 데이터 확인 중" : "전체 파싱"}</button>}
        </div>
        {actionError && <div role="alert" style={{ margin: "0 0 8px", padding: "8px 12px", border: "1px solid color-mix(in srgb, var(--danger) 45%, var(--border))", borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--danger) 7%, var(--bg-panel))", color: "var(--danger)", fontSize: 12 }}>{actionError}</div>}
        {artifactLoading && <div role="status" style={{ display: "flex", alignItems: "center", gap: 6, margin: "0 0 8px", color: "var(--text-faint)", fontSize: 11.5 }}><CircularProgress size={13} thickness={5} aria-hidden="true" />실행할 아티팩트 목록 확인 중</div>}
        {artifactError && <div role="alert" style={{ display: "flex", alignItems: "center", gap: 8, margin: "0 0 8px", padding: "8px 12px", border: "1px solid color-mix(in srgb, var(--danger) 45%, var(--border))", borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--danger) 7%, var(--bg-panel))", color: "var(--danger)", fontSize: 12 }}>{artifactError} 파싱을 시작할 수 없습니다.<button type="button" onClick={() => setArtifactLoadAttempt((attempt) => attempt + 1)} style={{ ...linkButtonStyle, marginLeft: 0 }}>다시 시도</button></div>}
        {!artifactLoading && !artifactError && artifacts.length === 0 && <div role="status" style={{ margin: "0 0 8px", color: "var(--warning)", fontSize: 12 }}>실행 가능한 아티팩트가 없습니다. 파싱을 시작할 수 없습니다.</div>}
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
              return <HostLedgerRow key={host.id} host={host} report={report} reportSyncPending={reportSyncPending} activeRun={activeRun} terminalRun={terminalRun} hasActiveRuns={hasActiveRuns} artifactsReady={artifactsReady} eligibility={eligibility[host.id]} onRun={handleRun} onRetryMft={handleRetryMft} onCancel={handleCancelRun} onOpenHost={onOpenHost} onRequestDelete={openDeleteConfirm} onRecheckEligibility={() => setEligibilityAttempt((attempt) => attempt + 1)} onRename={openRename} />;
            })}
          </div>
        </div>
        {filteredHosts.length > HOSTS_PER_PAGE && <div style={{ display: "flex", justifyContent: "flex-end", padding: "8px 2px", flexShrink: 0 }}><PaginationControls ariaLabel="호스트 목록 페이지" page={hostPage} pageCount={pageCount} onChange={setHostPage} summary={`(${(pageStart + 1).toLocaleString()}–${Math.min(pageStart + HOSTS_PER_PAGE, filteredHosts.length).toLocaleString()} / ${filteredHosts.length.toLocaleString()})`} /></div>}
      </section>
      {renameHost && <RenameHostDialog value={renameName} saving={renaming} error={renameError} onChange={setRenameName} onClose={() => { if (!renaming) setRenameHost(null); }} onSave={() => void handleRenameHost()} />}
      {deleteTarget && <DeleteHostDialog host={deleteTarget} deleting={deleting} error={actionError} onClose={() => { if (!deleting) { setDeleteTarget(null); setActionError(null); } }} onConfirm={() => void handleDelete(deleteTarget.id)} />}
      {resetOpen && <ResetHostsDialog count={hosts.length} resetting={resetting} error={resetError} onClose={() => { if (!resetting) setResetOpen(false); }} onConfirm={() => void handleReset()} />}
    </div>
  );
}

function HostLedgerRow({
  host, report, reportSyncPending, activeRun, terminalRun, hasActiveRuns, artifactsReady, eligibility,
  onRun, onRetryMft, onCancel, onOpenHost, onRequestDelete, onRecheckEligibility, onRename,
}: {
  host: Host;
  report?: ParseReport | null;
  reportSyncPending: boolean;
  activeRun?: PipelineRunItem;
  /** Last in-session terminal update fills the small refresh gap only. */
  terminalRun?: PipelineRunItem;
  hasActiveRuns: boolean;
  artifactsReady: boolean;
  eligibility?: ParseEligibilityEntry;
  onRun: (hostId: string) => void;
  onRetryMft: (hostId: string) => void;
  onCancel: (runId: string) => void;
  onOpenHost: (host: Host) => void;
  onRequestDelete: (host: Host) => void;
  onRecheckEligibility: () => void;
  onRename: (host: Host) => void;
}) {
  const [logOpen, setLogOpen] = useState(false);
  const logPanelId = useId();
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
  const blockedLabel = parseBlockedLabel(eligibility);
  const parseDisabled = hasActiveRuns || !artifactsReady || !canStartParse(eligibility);
  const parseHint = !artifactsReady
    ? "실행할 아티팩트 목록을 확인하지 못했습니다."
    : hasActiveRuns
      ? "다른 호스트 파싱이 끝난 뒤 실행할 수 있습니다."
      : blockedLabel ?? undefined;
  // Only expose the confirmed run's stored log.
  const showLogAction = Boolean(report) && !activeRun && !reportSyncPending;
  const terminalStatus = terminalRun?.status === "complete" ? "ok" : terminalRun?.status;
  const displayStatus = activeRun?.status ?? terminalStatus ?? host.lastRunStatus;
  const progress = activeRun && !isQueued ? hostProgress(activeRun) : null;
  // 카드 타일 색 = 실행 상태 신호.
  const tileColor = activeRun ? "var(--accent)" : displayStatus === "ok" ? "var(--success)" : displayStatus === "error" ? "var(--danger)" : displayStatus ? "var(--warning)" : "var(--text-dim)";
  // 카드 = 세로 구성: [헤더 행 + 우측 액션] 위, 펼친 실행 로그 패널이 아래
  // 전체 폭. 로그 패널을 좌측 컬럼에 가두면 우측 액션 밑이 크게 비어 보인다.
  return <article style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 8, padding: "11px 14px", border: `1px solid ${activeRun ? "color-mix(in srgb, var(--accent) 45%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)", background: activeRun ? "color-mix(in srgb, var(--accent) 5%, var(--bg-panel))" : "var(--bg-panel)", transition: "border-color .18s ease" }}>
    <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
    <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", alignItems: "stretch", gap: 6 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
      <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${tileColor} 15%, transparent)` }}>
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
    {progress && <div style={{ gridColumn: "1 / -1" }}>
      {progress.overview ? <InlineParseProgress bar={progress.overview} /> : <InlineParseProgress bar={progress.parse} />}
    </div>}
    {activeRun?.failedArtifacts.length ? <div role="alert" style={{ gridColumn: "1 / -1", padding: "0 0 6px", color: "var(--danger)", fontSize: 12 }}>파싱 실패: {activeRun.failedArtifacts.join(", ")}</div> : null}
    </div>
    <div className="host-ledger-actions">
      {canOpenResult && <button className="nm-btn" type="button" onClick={() => onOpenHost(host)} aria-label={`${host.name} 결과 보기`} style={{ ...neutralButtonStyle, padding: "8px 14px", fontSize: 12.5 }}><VisibilityOutlinedIcon sx={{ fontSize: 16 }} />결과 보기</button>}
      {activeRun ? <button className="nm-btn" type="button" onClick={() => onCancel(activeRun.runId)} style={{ ...dangerButtonStyle, padding: "8px 14px", fontSize: 12.5 }}><CancelOutlinedIcon sx={{ fontSize: 16 }} />{isQueued ? "대기 취소" : "취소"}</button> : <button className="nm-btn" type="button" onClick={() => onRun(host.id)} disabled={parseDisabled} title={parseHint} aria-label={`${host.name} 파싱`} style={{ ...primaryButtonStyle, padding: "8px 14px", fontSize: 12.5, opacity: parseDisabled ? .5 : 1 }}><PlayArrowIcon sx={{ fontSize: 16 }} />파싱</button>}
      {/* UI-01: 실행 로그 토글은 결과 보기·파싱과 같은 행에 둔다. */}
      {showLogAction && <button className="nm-btn" type="button" aria-expanded={logOpen} aria-controls={logPanelId} aria-label={`${host.name} 로그 확인`} onClick={() => setLogOpen((open) => !open)} style={{ ...neutralButtonStyle, padding: "8px 14px", fontSize: 12.5 }}><DescriptionOutlinedIcon sx={{ fontSize: 16 }} />로그 확인{logOpen ? <ExpandLessIcon sx={{ fontSize: 15 }} /> : <ExpandMoreIcon sx={{ fontSize: 15 }} />}</button>}
      <span aria-hidden="true" className="host-ledger-action-divider" />
      <button className="nm-btn" type="button" onClick={() => onRename(host)} disabled={!!activeRun} aria-label={`${host.name} 수정`} title="호스트 표시 이름 변경" style={{ ...neutralButtonStyle, padding: "8px 14px", fontSize: 12.5, cursor: activeRun ? "default" : "pointer", opacity: activeRun ? .4 : 1 }}><EditOutlinedIcon sx={{ fontSize: 16 }} />수정</button>
      <button className="nm-btn" type="button" onClick={() => onRequestDelete(host)} disabled={!!activeRun} aria-label={`${host.name} 삭제`} title="호스트 삭제 (원본 수집 데이터는 유지)" style={{ ...neutralButtonStyle, padding: "8px 14px", fontSize: 12.5, color: "var(--danger)", cursor: activeRun ? "default" : "pointer", opacity: activeRun ? .4 : 1 }}><DeleteOutlineIcon sx={{ fontSize: 16 }} />삭제</button>
      {!activeRun && blockedLabel && <span role={eligibility?.status === "error" ? "alert" : undefined} style={{ flexBasis: "100%", display: "inline-flex", alignItems: "center", justifyContent: "flex-end", gap: 5, color: eligibility?.status === "error" ? "var(--danger)" : "var(--text-faint)", fontSize: 11.5 }}>
        {blockedLabel}
        {eligibility?.status === "error" && <button type="button" onClick={onRecheckEligibility} style={{ ...linkButtonStyle, marginLeft: 0 }}>다시 확인</button>}
      </span>}
    </div>
    </div>
    {/* A host-level fallback status can belong to the previous run. Do not
        surface it until the exact terminal manifest has passed the same
        cache/run-id gate as the publication controls above.
        UI-01: 우측 `로그 확인`으로 여는 패널은 헤더 행 아래 전체 폭을 쓴다. */}
    {showLogAction && logOpen && report && <RunLogPanel id={logPanelId} host={host} report={report} onRetryMft={() => onRetryMft(host.id)} />}
  </article>;
}
