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
  doneArtifacts: Set<string>;
  totalSteps: number;
  completedSteps: number;
  runComplete: boolean;
  /** running, or finished-and-not-yet-dismissed (so the banner stays up). */
  active: boolean;
  percent: number;
  stepLabel: string;
  hadError: boolean;
  start: (opts: StartOpts) => Promise<void>;
  cancel: () => Promise<void>;
  dismiss: () => void;
}

// The parsing run lives here — a hook mounted ONCE at the top level (Home), so
// the child process's log stream keeps being captured and the progress keeps
// updating even when the user navigates to a different screen mid-parse. The
// actual work already runs in the Electron main process; this just makes the
// renderer-side state survive component unmounts.
const MAX_LOG_LINES = 2000;

export function usePipelineRun(onDone?: () => void): PipelineRun {
  const [runningHostId, setRunningHostId] = useState<string | null>(null);
  const [runningHostName, setRunningHostName] = useState<string | null>(null);
  const [logs, setLogs] = useState<PipelineLogEntry[]>([]);
  const [currentArtifact, setCurrentArtifact] = useState<string | null>(null);
  const [doneArtifacts, setDoneArtifacts] = useState<Set<string>>(new Set());
  const [totalSteps, setTotalSteps] = useState(0);
  const [completedSteps, setCompletedSteps] = useState(0);
  const [runComplete, setRunComplete] = useState(false);
  const [dismissed, setDismissed] = useState(true);
  const currentRef = useRef<string | null>(null);
  const onDoneRef = useRef(onDone);
  /** Set when the user cancels, so the pending runHost() promise doesn't
   * resurrect the progress UI as "완료" when it eventually resolves. */
  const cancelledRef = useRef(false);
  onDoneRef.current = onDone;

  // Mark the current section done (✓) — a section is finished once the next
  // one starts (or the run ends). Progress counting happens on section START.
  function flushCurrentSection() {
    const prev = currentRef.current;
    if (prev) setDoneArtifacts((done) => new Set(done).add(prev));
    currentRef.current = null;
  }

  useEffect(() => {
    const unsubscribe = window.api.onPipelineLog((entry) => {
      // Keep only the most recent lines. A verbose run (thousands of source
      // paths) would otherwise make `[...prev, entry]` copy an ever-growing
      // array on every single line — O(n²) — and pile up as many DOM nodes,
      // freezing the viewer. Bounding the buffer keeps each append O(cap).
      setLogs((prev) =>
        prev.length >= MAX_LOG_LINES
          ? [...prev.slice(prev.length - MAX_LOG_LINES + 1), entry]
          : [...prev, entry],
      );
      const match = entry.line.match(/^=== (.+) ===$/);
      if (match) {
        flushCurrentSection();
        currentRef.current = match[1];
        setCurrentArtifact(match[1]);
        setCompletedSteps((c) => c + 1);
      }
    });
    return unsubscribe;
  }, []);

  async function start(opts: StartOpts) {
    cancelledRef.current = false;
    setRunningHostId(opts.hostId);
    setRunningHostName(opts.hostName);
    setLogs([]);
    currentRef.current = null;
    setCurrentArtifact(null);
    setDoneArtifacts(new Set());
    setCompletedSteps(0);
    setRunComplete(false);
    setDismissed(false);
    setTotalSteps((opts.only ? opts.only.length : opts.totalArtifacts) + 1);

    await window.api.runHost({ caseId: opts.caseId, hostId: opts.hostId, only: opts.only });

    // A cancelled run already tore the UI down in cancel(); don't flip it back
    // to "완료" when the backend finally returns.
    if (cancelledRef.current) {
      cancelledRef.current = false;
      onDoneRef.current?.();
      return;
    }
    flushCurrentSection();
    setRunningHostId(null);
    setCurrentArtifact(null);
    setRunComplete(true);
    onDoneRef.current?.();
  }

  // Parsing runs in a child process, so cancel kills it outright — the work
  // stops immediately, not at the next poll point. The pending runHost()
  // promise still resolves afterwards; cancelledRef keeps it from flipping the
  // UI back to "완료".
  async function cancel() {
    cancelledRef.current = true;
    void window.api.cancelPipeline();
    flushCurrentSection();
    setRunningHostId(null);
    setCurrentArtifact(null);
    setRunComplete(false);
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
      : currentArtifact ? `${currentArtifact} 파싱 중…` : runningHostId ? "준비 중…" : "대기 중";
  const active = !!runningHostId || (runComplete && !dismissed);

  return {
    runningHostId, runningHostName, logs, currentArtifact, doneArtifacts,
    totalSteps, completedSteps, runComplete, active, percent, stepLabel, hadError,
    start, cancel, dismiss,
  };
}
