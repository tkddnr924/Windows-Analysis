"use client";

import { useEffect, useRef, useState } from "react";
import type { PipelineLogEntry } from "@/lib/types";

export interface StartOpts {
  caseId: string;
  hostId: string;
  hostName: string;
  /** Subset of artifacts to run; undefined = all. */
  only?: string[];
  /** Total artifact count (for the step denominator). */
  totalArtifacts: number;
}

export interface PipelineRun {
  runningHostId: string | null;
  runningHostName: string | null;
  logs: PipelineLogEntry[];
  currentArtifact: string | null;
  /** Artifacts currently being parsed (several run in parallel). */
  runningArtifacts: string[];
  doneArtifacts: Set<string>;
  totalSteps: number;
  completedSteps: number;
  runComplete: boolean;
  /** Host whose parse has just completed, retained after runningHostId clears. */
  completedHostId: string | null;
  /** Artifact names that reported a recoverable parse failure in the latest run. */
  failedArtifacts: string[];
  /** running, or finished-and-not-yet-dismissed (so the banner stays up). */
  active: boolean;
  percent: number;
  stepLabel: string;
  hadError: boolean;
  /** Queue entries are independent per immutable backend run id. */
  runs: PipelineRunItem[];
  start: (opts: StartOpts) => Promise<void>;
  /** Cancels one immutable run; omit the id only for the legacy focused run. */
  cancel: (runId?: string) => Promise<void>;
  dismiss: () => void;
}

export interface PipelineRunItem {
  runId: string;
  hostId: string;
  hostName: string;
  status: "queued" | "running" | "complete" | "partial" | "error" | "cancelled";
  currentArtifact: string | null;
  runningArtifacts: string[];
  totalSteps: number;
  completedSteps: number;
  failedArtifacts: string[];
}

// The parsing run lives here — a hook mounted ONCE at the top level (Home), so
// the child process's log stream keeps being captured and the progress keeps
// updating even when the user navigates to a different screen mid-parse. The
// actual work already runs in the Electron main process; this just makes the
// renderer-side state survive component unmounts.
const MAX_LOG_LINES = 2000;

// Parser progress protocol: "=== <phase> ===" section markers plus
// per-artifact "[시작] X" / "[완료] X" lines — several artifacts parse in
// parallel, so progress is tracked per artifact instead of per section.
type LineSignal =
  | { kind: "section"; name: string }
  | { kind: "start"; name: string }
  | { kind: "done"; name: string }
  | { kind: "failure"; name: string }
  | { kind: "none" };

function interpretLine(line: string): LineSignal {
  const section = line.match(/^=== (.+) ===$/);
  if (section) return { kind: "section", name: section[1] };
  const start = line.match(/^\[시작\] (\S+)/);
  if (start) return { kind: "start", name: start[1] };
  const done = line.match(/^\[완료\] (\S+)/);
  if (done) return { kind: "done", name: done[1] };
  const failure = line.match(/^\[!\]\s+(.+?)\s+failed:/);
  if (failure) return { kind: "failure", name: failure[1].trim() };
  return { kind: "none" };
}

function runningLabel(running: string[]): string | null {
  return running.length ? running.join(" · ") : null;
}

function newRunId(): string {
  // This identifier is both an event key and a path-safe immutable log name.
  return `gui-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export function usePipelineRun(onDone?: () => void): PipelineRun {
  const [runningHostId, setRunningHostId] = useState<string | null>(null);
  const [runningHostName, setRunningHostName] = useState<string | null>(null);
  const [logs, setLogs] = useState<PipelineLogEntry[]>([]);
  const [currentArtifact, setCurrentArtifact] = useState<string | null>(null);
  const [runningArtifacts, setRunningArtifacts] = useState<string[]>([]);
  const [doneArtifacts, setDoneArtifacts] = useState<Set<string>>(new Set());
  const [totalSteps, setTotalSteps] = useState(0);
  const [completedSteps, setCompletedSteps] = useState(0);
  const [runComplete, setRunComplete] = useState(false);
  const [completedHostId, setCompletedHostId] = useState<string | null>(null);
  const [failedArtifacts, setFailedArtifacts] = useState<string[]>([]);
  const [dismissed, setDismissed] = useState(true);
  const [runs, setRuns] = useState<PipelineRunItem[]>([]);
  const runningRef = useRef<string[]>([]);
  const currentRunRef = useRef<string | null>(null);
  const onDoneRef = useRef(onDone);
  /** Immutable run ids cancelled by the analyst. A batch may have two active
   * hosts, so one global boolean would accidentally cancel the other host's
   * completion UI when its promise resolves. */
  const cancelledRunsRef = useRef<Set<string>>(new Set());
  onDoneRef.current = onDone;

  // A run's terminal state (or cancel) clears any still-running markers; the
  // percent jumps to 100 via runComplete, so no synthetic done-count is needed.
  function clearRunning() {
    runningRef.current = [];
    setRunningArtifacts([]);
  }

  useEffect(() => {
    const unsubscribe = window.api.onPipelineLog((entry) => {
      const signal = interpretLine(entry.line);
      setRuns((previous) => previous.map((run) => {
        if (run.runId !== entry.runId) return run;
        let running = run.runningArtifacts;
        let completed = run.completedSteps;
        let current = entry.status === "running" ? run.currentArtifact : null;
        let failed = run.failedArtifacts;
        if (signal.kind === "section") {
          if (signal.name === "_OVERVIEW") {
            running = [];
            current = "_OVERVIEW";
          } else if (signal.name === "파일 확인") {
            current = "파일 확인";
          } else if (signal.name === "파싱") {
            current = runningLabel(running);
          }
        } else if (signal.kind === "start") {
          if (!running.includes(signal.name)) running = [...running, signal.name];
          current = runningLabel(running);
        } else if ((signal.kind === "done" || signal.kind === "failure") && running.includes(signal.name)) {
          running = running.filter((name) => name !== signal.name);
          completed = Math.min(run.totalSteps, completed + 1);
          current = runningLabel(running);
          if (signal.kind === "failure" && !failed.includes(signal.name)) failed = [...failed, signal.name];
        }
        return {
          ...run,
          status: entry.status,
          currentArtifact: current,
          runningArtifacts: running,
          completedSteps: completed,
          failedArtifacts: failed,
        };
      }));
      // The legacy compact progress banner follows the latest user-selected
      // run. Other hosts remain independently visible via `runs`.
      if (entry.runId !== currentRunRef.current) return;
      // Keep only the most recent lines. A verbose run (thousands of source
      // paths) would otherwise make `[...prev, entry]` copy an ever-growing
      // array on every single line — O(n²) — and pile up as many DOM nodes,
      // freezing the viewer. Bounding the buffer keeps each append O(cap).
      setLogs((prev) =>
        prev.length >= MAX_LOG_LINES
          ? [...prev.slice(prev.length - MAX_LOG_LINES + 1), entry]
          : [...prev, entry],
      );
      if (signal.kind === "section") {
        if (signal.name === "_OVERVIEW") {
          clearRunning();
          setCurrentArtifact("_OVERVIEW");
        } else if (signal.name === "파일 확인") {
          setCurrentArtifact("파일 확인");
        } else if (signal.name === "파싱") {
          setCurrentArtifact(runningLabel(runningRef.current));
        }
      } else if (signal.kind === "start") {
        if (!runningRef.current.includes(signal.name)) {
          runningRef.current = [...runningRef.current, signal.name];
        }
        setRunningArtifacts(runningRef.current);
        setCurrentArtifact(runningLabel(runningRef.current));
      } else if ((signal.kind === "done" || signal.kind === "failure") && runningRef.current.includes(signal.name)) {
        const name = signal.name;
        runningRef.current = runningRef.current.filter((item) => item !== name);
        setRunningArtifacts(runningRef.current);
        setDoneArtifacts((done) => new Set(done).add(name));
        setCompletedSteps((c) => c + 1);
        setCurrentArtifact(runningLabel(runningRef.current));
        if (signal.kind === "failure") {
          setFailedArtifacts((previous) => previous.includes(name) ? previous : [...previous, name]);
        }
      }
    });
    return unsubscribe;
  }, []);

  async function start(opts: StartOpts) {
    const runId = newRunId();
    currentRunRef.current = runId;
    cancelledRunsRef.current.delete(runId);
    setRunningHostId(opts.hostId);
    setRunningHostName(opts.hostName);
    setLogs([]);
    runningRef.current = [];
    setRunningArtifacts([]);
    setCurrentArtifact(null);
    setDoneArtifacts(new Set());
    setCompletedSteps(0);
    setRunComplete(false);
    setCompletedHostId(null);
    setFailedArtifacts([]);
    setDismissed(false);
    setTotalSteps((opts.only ? opts.only.length : opts.totalArtifacts) + 1);
    setRuns((previous) => [...previous, {
      runId,
      hostId: opts.hostId,
      hostName: opts.hostName,
      status: "queued",
      currentArtifact: null,
      runningArtifacts: [],
      totalSteps: (opts.only ? opts.only.length : opts.totalArtifacts) + 1,
      completedSteps: 0,
      failedArtifacts: [],
    }]);

    try {
      const result = await window.api.runHost({ caseId: opts.caseId, hostId: opts.hostId, runId, only: opts.only });
      setRuns((previous) => previous.map((run) => run.runId === runId
        ? { ...run, status: result.status, currentArtifact: null }
        : run));
      if (result.status === "cancelled") {
        if (currentRunRef.current === runId) {
          setRunningHostId(null);
          setCurrentArtifact(null);
          setRunComplete(false);
          setDismissed(true);
        }
        // Every immutable run owns a persisted terminal state.  In a bounded
        // concurrent batch this may not be the latest clicked host, so do not
        // restrict the case refresh to `currentRunRef`.
        onDoneRef.current?.();
        return;
      }
      if (result.status === "error") setFailedArtifacts(["파서 실행"]);
      if (result.status === "partial") {
        setFailedArtifacts((previous) => previous.length ? previous : ["일부 아티팩트"]);
      }
    } catch {
      setRuns((previous) => previous.map((run) => run.runId === runId
        ? { ...run, status: "error", currentArtifact: null }
        : run));
      setFailedArtifacts(["파서 실행"]);
    }

    // A cancelled run already tore the UI down in cancel(); don't flip it back
    // to "완료" when the backend finally returns.
    if (cancelledRunsRef.current.delete(runId)) {
      onDoneRef.current?.();
      return;
    }
    if (currentRunRef.current === runId) {
      clearRunning();
      setRunningHostId(null);
      setCurrentArtifact(null);
      setCompletedHostId(opts.hostId);
      setRunComplete(true);
    }
    // Refresh host metadata for *every* terminal worker, not only the most
    // recently selected run.  The parent serializes stale refresh responses,
    // so two slots completing close together cannot roll back one another.
    onDoneRef.current?.();
  }

  // Parsing runs in a child process, so cancel kills it outright — the work
  // stops immediately, not at the next poll point. The pending runHost()
  // promise still resolves afterwards; cancelledRef keeps it from flipping the
  // UI back to "완료".
  async function cancel(runId?: string) {
    const targetRunId = runId ?? currentRunRef.current;
    void window.api.cancelPipeline(targetRunId ?? undefined);
    if (targetRunId) {
      cancelledRunsRef.current.add(targetRunId);
      setRuns((previous) => previous.map((run) => run.runId === targetRunId
        ? { ...run, status: "cancelled", currentArtifact: null }
        : run));
    }
    if (targetRunId && targetRunId !== currentRunRef.current) return;
    clearRunning();
    setRunningHostId(null);
    setCurrentArtifact(null);
    setRunComplete(false);
    setCompletedHostId(null);
    setFailedArtifacts([]);
    setDismissed(true);
  }

  function dismiss() {
    setDismissed(true);
    setRunComplete(false);
  }

  const hadError = logs.some((l) => l.line.includes("failed:") || l.line.includes("Traceback"));
  const percent = runComplete
    ? 100
    : runningHostId && totalSteps > 0
      ? Math.min(99, Math.round((completedSteps / totalSteps) * 100))
      : 0;
  const stepLabel = runComplete
    ? hadError ? "완료 (일부 오류)" : "완료"
    : currentArtifact === "_OVERVIEW"
      ? "종합 분석 생성 중…"
      : currentArtifact === "파일 확인"
        ? "원본 파일 확인 중…"
        : currentArtifact ? `${currentArtifact} 파싱 중…` : runningHostId ? "준비 중…" : "대기 중";
  // Several hosts can run concurrently.  A terminal latest-clicked host must
  // not hide the global notice while an earlier queue entry is still alive.
  // `dismissed` affects only the notice, never the backend scheduler.
  const hasLiveRuns = runs.some((run) => run.status === "queued" || run.status === "running");
  const active = !dismissed && (hasLiveRuns || runComplete);

  return {
    runningHostId, runningHostName, logs, currentArtifact, runningArtifacts, doneArtifacts,
    totalSteps, completedSteps, runComplete, completedHostId, failedArtifacts, active, percent, stepLabel, hadError, runs,
    start, cancel, dismiss,
  };
}
