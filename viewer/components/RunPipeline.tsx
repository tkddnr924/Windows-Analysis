"use client";

import { useEffect, useRef, useState } from "react";
import type { Case, Host, PipelineLogEntry } from "@/lib/types";

interface RunPipelineProps {
  activeCase: Case;
  onBack: () => void;
  onChanged: () => void;
  onOpenHost: (h: Host) => void;
}

const primaryButtonStyle: React.CSSProperties = {
  padding: "7px 16px",
  background: "var(--accent-emphasis)",
  color: "#ffffff",
  fontWeight: 600,
  border: "none",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  whiteSpace: "nowrap",
};

const dangerButtonStyle: React.CSSProperties = {
  padding: "7px 16px",
  background: "transparent",
  color: "var(--danger)",
  border: "1px solid var(--danger)",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  whiteSpace: "nowrap",
};

const successButtonStyle: React.CSSProperties = {
  padding: "7px 16px",
  background: "var(--success-subtle)",
  color: "var(--success)",
  border: "1px solid var(--success)",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  fontWeight: 600,
  whiteSpace: "nowrap",
};

const linkButtonStyle: React.CSSProperties = {
  marginLeft: 10,
  fontSize: 11,
  background: "transparent",
  border: "none",
  color: "var(--accent)",
  cursor: "pointer",
  fontWeight: 600,
};

function StatusPill({ status }: { status: string | null }) {
  if (status === "ok")
    return <span style={{ fontSize: 11, fontWeight: 600, color: "var(--success)", background: "var(--success-subtle)", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}>✓ 완료</span>;
  if (status === "error")
    return <span style={{ fontSize: 11, fontWeight: 600, color: "var(--danger)", background: "var(--danger-subtle)", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}>⛔ 오류</span>;
  return <span style={{ fontSize: 11, color: "var(--text-faint)", background: "var(--bg-elevated)", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}>미실행</span>;
}

export default function RunPipeline({ activeCase, onBack, onChanged, onOpenHost }: RunPipelineProps) {
  const hosts = activeCase.hosts;

  const [newHostName, setNewHostName] = useState("");
  const [newHostTarget, setNewHostTarget] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [artifacts, setArtifacts] = useState<string[]>([]);
  const [selectedArtifacts, setSelectedArtifacts] = useState<Set<string>>(new Set());
  const [runningHostId, setRunningHostId] = useState<string | null>(null);
  const [logs, setLogs] = useState<PipelineLogEntry[]>([]);
  const [currentArtifact, setCurrentArtifact] = useState<string | null>(null);
  const [doneArtifacts, setDoneArtifacts] = useState<Set<string>>(new Set());
  const [totalSteps, setTotalSteps] = useState(0);
  const [completedSteps, setCompletedSteps] = useState(0);
  const [runComplete, setRunComplete] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);
  // Latest section header seen ("=== X ==="). A section is only counted as
  // done once the NEXT section starts — so the ref lets us also flush the very
  // last section on completion, which otherwise never gets a following header
  // (e.g. an Amcache-only run ends on "_OVERVIEW", or the last artifact of a
  // full run), leaving its ✓ and the step counter permanently one short.
  const currentRef = useRef<string | null>(null);

  function flushCurrentSection() {
    const prev = currentRef.current;
    if (prev) {
      setDoneArtifacts((done) => new Set(done).add(prev));
      setCompletedSteps((c) => c + 1);
    }
    currentRef.current = null;
  }

  useEffect(() => {
    window.api.listArtifacts().then((names) => {
      setArtifacts(names);
      setSelectedArtifacts(new Set(names));
    });
  }, []);

  useEffect(() => {
    const unsubscribe = window.api.onPipelineLog((entry) => {
      setLogs((prev) => [...prev, entry]);
      const match = entry.line.match(/^=== (.+) ===$/);
      if (match) {
        flushCurrentSection();
        currentRef.current = match[1];
        setCurrentArtifact(match[1]);
      }
    });
    return unsubscribe;
  }, []);

  useEffect(() => {
    if (showLog) logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs, showLog]);

  async function pickTarget() {
    const dir = await window.api.pickFolder();
    if (dir) setNewHostTarget(dir);
  }

  async function handleAddHost() {
    if (!newHostName.trim() || !newHostTarget) return;
    setCreating(true);
    try {
      await window.api.createHost(activeCase.id, newHostName.trim(), newHostTarget);
      setNewHostName("");
      setNewHostTarget(null);
      onChanged();
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

  async function handleRun(hostId: string) {
    const only = selectedArtifacts.size === artifacts.length ? undefined : Array.from(selectedArtifacts);
    setRunningHostId(hostId);
    setLogs([]);
    currentRef.current = null;
    setCurrentArtifact(null);
    setDoneArtifacts(new Set());
    setCompletedSteps(0);
    setRunComplete(false);
    setTotalSteps((only ? only.length : artifacts.length) + 1);

    await window.api.runHost({ caseId: activeCase.id, hostId, only });

    flushCurrentSection(); // count the final section (last artifact / _OVERVIEW)
    setRunningHostId(null);
    setCurrentArtifact(null);
    setRunComplete(true);
    onChanged();
  }

  async function handleCancel() {
    await window.api.cancelPipeline();
  }

  async function handleDelete(hostId: string) {
    setDeleting(true);
    try {
      await window.api.deleteHost(activeCase.id, hostId);
      onChanged();
    } finally {
      setDeleting(false);
      setConfirmDeleteId(null);
    }
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
  const barColor = hadError ? "var(--danger)" : runComplete ? "var(--success)" : "var(--accent)";

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: 24, gap: 22, overflow: "auto", maxWidth: 980, margin: "0 auto", width: "100%" }}>
      {/* breadcrumb */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button onClick={onBack} style={{ background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontSize: 12.5, fontWeight: 600 }}>
          ‹ 케이스 목록
        </button>
        <span style={{ color: "var(--text-faint)" }}>/</span>
        <span style={{ fontSize: 15, fontWeight: 700 }}>🗂️ {activeCase.name}</span>
        <span style={{ fontSize: 12, color: "var(--text-faint)" }}>호스트 {hosts.length}개</span>
      </div>

      {/* add host */}
      <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 18, boxShadow: "var(--shadow-card)" }}>
        <h3 style={{ margin: "0 0 12px", fontSize: 13.5 }}>🖥️ 새 호스트 추가</h3>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <input
            placeholder="호스트 이름 (예: BKMASTER)"
            value={newHostName}
            onChange={(e) => setNewHostName(e.target.value)}
            style={{ padding: "7px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", minWidth: 180 }}
          />
          <button onClick={pickTarget} style={{ padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer" }}>
            📁 수집 데이터 폴더
          </button>
          <span style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={newHostTarget ?? ""}>
            {newHostTarget ?? "선택 안 됨"}
          </span>
          <button
            onClick={handleAddHost}
            disabled={creating || !newHostName.trim() || !newHostTarget}
            style={{ ...primaryButtonStyle, marginLeft: "auto", opacity: creating || !newHostName.trim() || !newHostTarget ? 0.5 : 1 }}
          >
            호스트 추가
          </button>
        </div>
      </section>

      {/* artifact selection */}
      {artifacts.length > 0 && (
        <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 18, boxShadow: "var(--shadow-card)" }}>
          <div style={{ fontSize: 13, marginBottom: 10, display: "flex", alignItems: "center" }}>
            <span style={{ fontWeight: 700 }}>⚙️ 실행할 아티팩트</span>
            <span style={{ color: "var(--text-faint)", marginLeft: 6 }}>{selectedArtifacts.size}/{artifacts.length}</span>
            <button onClick={() => setSelectedArtifacts(new Set(artifacts))} disabled={!!runningHostId} style={linkButtonStyle}>전체 선택</button>
            <button onClick={() => setSelectedArtifacts(new Set())} disabled={!!runningHostId} style={linkButtonStyle}>전체 해제</button>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {artifacts.map((name) => {
              const isDone = doneArtifacts.has(name);
              const isCurrent = currentArtifact === name;
              const checked = selectedArtifacts.has(name);
              return (
                <label key={name} style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 12px", border: `1px solid ${isCurrent ? "var(--accent)" : checked ? "var(--border)" : "var(--border-subtle)"}`, borderRadius: "var(--radius-lg)", fontSize: 12.5, cursor: runningHostId ? "default" : "pointer", background: isCurrent ? "var(--accent-subtle)" : isDone ? "var(--success-subtle)" : checked ? "var(--bg-elevated)" : "transparent", color: checked ? "var(--text)" : "var(--text-faint)" }}>
                  <input type="checkbox" checked={checked} disabled={!!runningHostId} onChange={() => toggleArtifact(name)} />
                  {name}
                  {isDone && <span style={{ color: "var(--success)" }}>✓</span>}
                  {isCurrent && <span style={{ color: "var(--accent)" }}>●</span>}
                </label>
              );
            })}
          </div>
        </section>
      )}

      {/* host list */}
      <section style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 120 }}>
        <h3 style={{ margin: "0 0 10px", fontSize: 13.5 }}>🖥️ 호스트 목록</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {hosts.length === 0 && (
            <div style={{ padding: 24, textAlign: "center", color: "var(--text-faint)", border: "1px dashed var(--border)", borderRadius: "var(--radius-lg)" }}>
              이 케이스에 호스트가 없습니다. 위에서 호스트를 추가하세요.
            </div>
          )}
          {hosts.map((h) => (
            <div key={h.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)" }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 13.5 }}>🖥️ {h.name}</span>
                  <StatusPill status={h.lastRunStatus} />
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 3 }} title={h.targetDir}>
                  📁 {h.targetDir}
                </div>
                {h.lastRunAt && <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>마지막 실행: {h.lastRunAt}</div>}
              </div>
              {confirmDeleteId === h.id ? (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 12, color: "var(--danger)" }}>삭제할까요?</span>
                  <button onClick={() => handleDelete(h.id)} disabled={deleting} style={{ ...dangerButtonStyle, opacity: deleting ? 0.5 : 1 }}>삭제</button>
                  <button onClick={() => setConfirmDeleteId(null)} disabled={deleting} style={{ padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12.5 }}>취소</button>
                </div>
              ) : (
                <>
                  {runningHostId === h.id ? (
                    <button onClick={handleCancel} style={dangerButtonStyle}>취소</button>
                  ) : (
                    <button onClick={() => handleRun(h.id)} disabled={!!runningHostId || selectedArtifacts.size === 0} style={{ ...primaryButtonStyle, opacity: !!runningHostId || selectedArtifacts.size === 0 ? 0.5 : 1 }}>
                      ▶ 파싱
                    </button>
                  )}
                  {h.lastRunStatus === "ok" && (
                    <button onClick={() => onOpenHost(h)} style={successButtonStyle}>결과 보기 →</button>
                  )}
                  <button onClick={() => setConfirmDeleteId(h.id)} disabled={!!runningHostId} title="호스트 삭제 (분석 결과만, 원본 수집 데이터는 유지)" style={{ padding: "7px 10px", background: "transparent", color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: runningHostId ? "default" : "pointer", fontSize: 12.5, opacity: runningHostId ? 0.4 : 1 }}>🗑</button>
                </>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* progress */}
      <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 18, boxShadow: "var(--shadow-card)", display: "flex", flexDirection: "column", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: hadError ? "var(--danger)" : "var(--text)" }}>
            {runningHostId && <span style={{ marginRight: 6 }}>⏳</span>}
            {stepLabel}
          </span>
          <span style={{ fontSize: 22, fontWeight: 700, fontVariantNumeric: "tabular-nums", color: barColor }}>{percent}%</span>
        </div>
        <div style={{ height: 8, background: "var(--bg-elevated)", borderRadius: 999, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${percent}%`, background: barColor, borderRadius: 999, transition: "width 0.3s ease" }} />
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 11.5, color: "var(--text-faint)" }}>
          <span>{totalSteps > 0 ? `${Math.min(completedSteps, totalSteps)} / ${totalSteps} 단계` : "호스트의 ‘파싱’을 누르면 진행 상황이 표시됩니다."}</span>
          {logs.length > 0 && (
            <button onClick={() => setShowLog((v) => !v)} style={{ background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontSize: 11.5, fontWeight: 600 }}>
              {showLog ? "로그 숨기기" : "자세한 로그 보기"}
            </button>
          )}
        </div>
        {showLog && (
          <div style={{ marginTop: 4, maxHeight: 220, background: "var(--bg)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: 12, fontFamily: "var(--mono)", fontSize: 12, overflow: "auto" }}>
            {logs.map((entry, i) => (
              <div key={i} style={{ color: entry.stream === "stderr" ? "var(--danger)" : "var(--text-dim)", whiteSpace: "pre-wrap" }}>{entry.line}</div>
            ))}
            <div ref={logEndRef} />
          </div>
        )}
      </div>
    </div>
  );
}
