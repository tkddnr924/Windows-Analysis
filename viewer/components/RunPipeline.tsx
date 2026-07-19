"use client";

import { useEffect, useRef, useState } from "react";
import type { CaseSummary, PipelineLogEntry } from "@/lib/types";

interface RunPipelineProps {
  cases: CaseSummary[];
  onCasesChanged: () => void;
  onOpenResults: (c: CaseSummary) => void;
}

const linkButtonStyle: React.CSSProperties = {
  marginLeft: 10,
  fontSize: 11,
  background: "transparent",
  border: "none",
  color: "var(--accent)",
  cursor: "pointer",
  fontWeight: 600,
};

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

function StatusPill({ status }: { status: string | null }) {
  if (status === "ok") {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, fontWeight: 600, color: "var(--success)", background: "var(--success-subtle)", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}>
        ✓ 완료
      </span>
    );
  }
  if (status === "error") {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, fontWeight: 600, color: "var(--danger)", background: "var(--danger-subtle)", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}>
        ⛔ 오류
      </span>
    );
  }
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--text-faint)", background: "var(--bg-elevated)", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}>
      미실행
    </span>
  );
}

export default function RunPipeline({ cases, onCasesChanged, onOpenResults }: RunPipelineProps) {
  const [newCaseName, setNewCaseName] = useState("");
  const [newCaseTarget, setNewCaseTarget] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [artifacts, setArtifacts] = useState<string[]>([]);
  const [selectedArtifacts, setSelectedArtifacts] = useState<Set<string>>(new Set());
  const [runningCaseId, setRunningCaseId] = useState<string | null>(null);
  const [logs, setLogs] = useState<PipelineLogEntry[]>([]);
  const [currentArtifact, setCurrentArtifact] = useState<string | null>(null);
  const [doneArtifacts, setDoneArtifacts] = useState<Set<string>>(new Set());
  const logEndRef = useRef<HTMLDivElement>(null);

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
        const name = match[1];
        setCurrentArtifact((prevCurrent) => {
          if (prevCurrent) setDoneArtifacts((done) => new Set(done).add(prevCurrent));
          return name;
        });
      }
    });
    return unsubscribe;
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs]);

  async function pickTarget() {
    const dir = await window.api.pickFolder();
    if (dir) setNewCaseTarget(dir);
  }

  async function handleCreateCase() {
    if (!newCaseName.trim() || !newCaseTarget) return;
    setCreating(true);
    try {
      await window.api.createCase(newCaseName.trim(), newCaseTarget);
      setNewCaseName("");
      setNewCaseTarget(null);
      onCasesChanged();
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

  async function handleRun(caseId: string) {
    setRunningCaseId(caseId);
    setLogs([]);
    setCurrentArtifact(null);
    setDoneArtifacts(new Set());

    const only = selectedArtifacts.size === artifacts.length ? undefined : Array.from(selectedArtifacts);
    await window.api.runCase({ caseId, only });

    setRunningCaseId(null);
    setCurrentArtifact(null);
    onCasesChanged();
  }

  async function handleCancel() {
    await window.api.cancelPipeline();
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", width: "100%", padding: 24, gap: 24, overflow: "auto", maxWidth: 980, margin: "0 auto" }}>
      <section
        style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 18, boxShadow: "var(--shadow-card)" }}
      >
        <h3 style={{ margin: "0 0 12px", fontSize: 13.5, display: "flex", alignItems: "center", gap: 6 }}>🗂️ 새 케이스 생성</h3>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <input
            placeholder="케이스 이름"
            value={newCaseName}
            onChange={(e) => setNewCaseName(e.target.value)}
            style={{
              padding: "7px 10px",
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              color: "var(--text)",
              minWidth: 160,
            }}
          />
          <button
            onClick={pickTarget}
            style={{ padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer" }}
          >
            📁 대상 폴더 선택
          </button>
          <span
            style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
            title={newCaseTarget ?? ""}
          >
            {newCaseTarget ?? "선택 안 됨"}
          </span>
          <button
            onClick={handleCreateCase}
            disabled={creating || !newCaseName.trim() || !newCaseTarget}
            style={{
              ...primaryButtonStyle,
              marginLeft: "auto",
              opacity: creating || !newCaseName.trim() || !newCaseTarget ? 0.5 : 1,
              cursor: creating || !newCaseName.trim() || !newCaseTarget ? "default" : "pointer",
            }}
          >
            케이스 생성
          </button>
        </div>
      </section>

      {artifacts.length > 0 && (
        <section
          style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 18, boxShadow: "var(--shadow-card)" }}
        >
          <div style={{ fontSize: 13, marginBottom: 10, display: "flex", alignItems: "center" }}>
            <span style={{ fontWeight: 700 }}>⚙️ 실행할 아티팩트</span>
            <span style={{ color: "var(--text-faint)", marginLeft: 6 }}>{selectedArtifacts.size}/{artifacts.length}</span>
            <button onClick={() => setSelectedArtifacts(new Set(artifacts))} disabled={!!runningCaseId} style={linkButtonStyle}>
              전체 선택
            </button>
            <button onClick={() => setSelectedArtifacts(new Set())} disabled={!!runningCaseId} style={linkButtonStyle}>
              전체 해제
            </button>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {artifacts.map((name) => {
              const isDone = doneArtifacts.has(name);
              const isCurrent = currentArtifact === name;
              const checked = selectedArtifacts.has(name);
              return (
                <label
                  key={name}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "5px 12px",
                    border: `1px solid ${isCurrent ? "var(--accent)" : checked ? "var(--border)" : "var(--border-subtle)"}`,
                    borderRadius: "var(--radius-lg)",
                    fontSize: 12.5,
                    cursor: runningCaseId ? "default" : "pointer",
                    background: isCurrent ? "var(--accent-subtle)" : isDone ? "var(--success-subtle)" : checked ? "var(--bg-elevated)" : "transparent",
                    color: checked ? "var(--text)" : "var(--text-faint)",
                    transition: "background-color 0.15s ease",
                  }}
                >
                  <input type="checkbox" checked={checked} disabled={!!runningCaseId} onChange={() => toggleArtifact(name)} />
                  {name}
                  {isDone && <span style={{ color: "var(--success)" }}>✓</span>}
                  {isCurrent && <span style={{ color: "var(--accent)" }}>●</span>}
                </label>
              );
            })}
          </div>
        </section>
      )}

      <section style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 160 }}>
        <h3 style={{ margin: "0 0 10px", fontSize: 13.5, display: "flex", alignItems: "center", gap: 6 }}>📋 케이스 목록</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 10, overflowY: "auto" }}>
          {cases.length === 0 && (
            <div style={{ padding: 24, textAlign: "center", color: "var(--text-faint)", border: "1px dashed var(--border)", borderRadius: "var(--radius-lg)" }}>
              등록된 케이스가 없습니다. 위에서 새 케이스를 만들어 보세요.
            </div>
          )}
          {cases.map((c) => (
            <div
              key={c.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "14px 16px",
                background: "var(--bg-panel)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-lg)",
                boxShadow: "var(--shadow-card)",
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 13.5 }}>{c.name}</span>
                  <StatusPill status={c.lastRunStatus} />
                </div>
                <div
                  style={{ fontSize: 11.5, color: "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 3 }}
                  title={c.targetDir}
                >
                  📁 {c.targetDir}
                </div>
                {c.lastRunAt && <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>마지막 실행: {c.lastRunAt}</div>}
              </div>
              {runningCaseId === c.id ? (
                <button onClick={handleCancel} style={dangerButtonStyle}>
                  취소
                </button>
              ) : (
                <button
                  onClick={() => handleRun(c.id)}
                  disabled={!!runningCaseId || selectedArtifacts.size === 0}
                  style={{ ...primaryButtonStyle, opacity: !!runningCaseId || selectedArtifacts.size === 0 ? 0.5 : 1 }}
                >
                  ▶ 파싱 시작
                </button>
              )}
              {c.lastRunStatus === "ok" && (
                <button onClick={() => onOpenResults(c)} style={successButtonStyle}>
                  결과 보기 →
                </button>
              )}
            </div>
          ))}
        </div>
      </section>

      <div
        style={{
          minHeight: 160,
          maxHeight: 260,
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
      >
        <div style={{ padding: "8px 14px", borderBottom: "1px solid var(--border)", fontSize: 11, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.6 }}>
          로그
        </div>
        <div style={{ padding: 12, fontFamily: "var(--mono)", fontSize: 12, overflow: "auto", flex: 1 }}>
          {logs.length === 0 && <div style={{ color: "var(--text-faint)" }}>로그가 여기에 표시됩니다.</div>}
          {logs.map((entry, i) => (
            <div key={i} style={{ color: entry.stream === "stderr" ? "var(--danger)" : "var(--text-dim)", whiteSpace: "pre-wrap" }}>
              {entry.line}
            </div>
          ))}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
}
