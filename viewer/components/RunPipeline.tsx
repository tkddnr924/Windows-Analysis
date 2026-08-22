"use client";

import { useEffect, useState } from "react";
import AddIcon from "@mui/icons-material/Add";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutlineOutlined";
import DeselectIcon from "@mui/icons-material/Deselect";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutlineOutlined";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import MemoryOutlinedIcon from "@mui/icons-material/MemoryOutlined";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SelectAllIcon from "@mui/icons-material/SelectAll";
import TaskAltIcon from "@mui/icons-material/TaskAlt";
import TimerOutlinedIcon from "@mui/icons-material/TimerOutlined";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import type { Case, Host } from "@/lib/types";
import type { PipelineRun } from "@/lib/usePipelineRun";

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
  color: "#ffffff",
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
  background: "transparent",
  color: "var(--danger)",
  border: "1px solid var(--danger)",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12.5,
  whiteSpace: "nowrap",
};

const successButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 5,
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

// "45초" / "3분 12초" / "1시간 4분" from a duration in seconds.
function formatDuration(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return `${s}초`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}분 ${s % 60}초`;
  return `${Math.floor(m / 60)}시간 ${m % 60}분`;
}

function StatusPill({ status }: { status: string | null }) {
  if (status === "ok")
    return <span style={statusPillStyle("var(--success)", "var(--success-subtle)")}><TaskAltIcon sx={{ fontSize: 13 }} />완료</span>;
  if (status === "error")
    return <span style={statusPillStyle("var(--danger)", "var(--danger-subtle)")}><ErrorOutlineIcon sx={{ fontSize: 13 }} />오류</span>;
  return <span style={statusPillStyle("var(--text-faint)", "var(--bg-elevated)")}><TimerOutlinedIcon sx={{ fontSize: 13 }} />미실행</span>;
}

function statusPillStyle(color: string, background: string): React.CSSProperties {
  return { display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, fontWeight: 600, color, background, padding: "2px 8px", borderRadius: "var(--radius-lg)" };
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
    <div style={{ padding: "8px 18px 16px", display: "flex", flexDirection: "column", gap: 9 }}>
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

export default function RunPipeline({ activeCase, onChanged, onOpenHost, run }: RunPipelineProps) {
  const hosts = activeCase.hosts;

  const [newHostName, setNewHostName] = useState("");
  const [newHostTarget, setNewHostTarget] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [artifacts, setArtifacts] = useState<string[]>([]);
  const [selectedArtifacts, setSelectedArtifacts] = useState<Set<string>>(new Set());
  const [artifactListExpanded, setArtifactListExpanded] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  // The parse state (runningHostId, logs, progress, …) lives in the `run` hook
  // hoisted to Home so it survives navigating away mid-parse.
  const { runningHostId, currentArtifact, totalSteps, completedSteps, percent, stepLabel, runComplete, completedHostId, failedArtifacts } = run;

  useEffect(() => {
    window.api.listArtifacts().then((names) => {
      setArtifacts(names);
      setSelectedArtifacts(new Set(names));
    });
  }, []);

  async function pickTarget() {
    const dir = await window.api.pickFolder();
    if (!dir) return;
    setNewHostTarget(dir);
    const suggestedName = folderName(dir);
    if (suggestedName) setNewHostName(suggestedName);
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

  function handleRun(hostId: string) {
    const host = hosts.find((h) => h.id === hostId);
    const only = selectedArtifacts.size === artifacts.length ? undefined : Array.from(selectedArtifacts);
    // run.start awaits the child process and refreshes the case list (Home's
    // onDone) on completion — so the host list here updates without onChanged.
    run.start({ caseId: activeCase.id, hostId, hostName: host?.name ?? "", only, totalArtifacts: artifacts.length });
  }

  function handleCancel() {
    run.cancel();
  }

  // Parse every host in the case, one after another (run.start resolves when a
  // host finishes). The global progress bar tracks whichever host is running.
  async function handleRunAll() {
    const only = selectedArtifacts.size === artifacts.length ? undefined : Array.from(selectedArtifacts);
    for (const h of hosts) {
      await run.start({ caseId: activeCase.id, hostId: h.id, hostName: h.name, only, totalArtifacts: artifacts.length });
    }
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

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "42px 32px 28px", gap: 22, overflow: "hidden", maxWidth: 1120, margin: "0 auto", width: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span className="dfir-page-title">호스트 등록</span>
        <span className="dfir-tag" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><DnsOutlinedIcon sx={{ fontSize: 14 }} />등록된 호스트 {hosts.length}개</span>
      </div>

      {/* add host */}
      <section className="dfir-surface" style={{ padding: 22 }}>
        <div className="dfir-section-label" style={{ marginBottom: 7 }}>EVIDENCE SOURCE</div>
        <h3 style={{ margin: "0 0 14px", fontSize: 16 }}>새 호스트 추가</h3>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <input
            placeholder="호스트 이름 (예: WEB-01)"
            value={newHostName}
            onChange={(e) => setNewHostName(e.target.value)}
            style={{ padding: "7px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", minWidth: 180 }}
          />
          <button onClick={pickTarget} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer" }}>
            <FolderOpenOutlinedIcon sx={{ fontSize: 16 }} />수집 데이터 폴더
          </button>
          <span style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={newHostTarget ?? ""}>
            {newHostTarget ?? "선택 안 됨"}
          </span>
          <button
            onClick={handleAddHost}
            disabled={creating || !newHostName.trim() || !newHostTarget}
            style={{ ...primaryButtonStyle, marginLeft: "auto", opacity: creating || !newHostName.trim() || !newHostTarget ? 0.5 : 1 }}
          >
            <AddIcon sx={{ fontSize: 16 }} />호스트 추가
          </button>
        </div>
      </section>

      {/* artifact selection */}
      {artifacts.length > 0 && (
        <section className="dfir-surface" style={{ padding: 22 }}>
          <div style={{ fontSize: 13, marginBottom: 10, display: "flex", alignItems: "center" }}>
            <span style={{ fontWeight: 700 }}>실행할 아티팩트</span>
            <span className="dfir-tag" style={{ marginLeft: 4, display: "inline-flex", alignItems: "center", gap: 4 }}><MemoryOutlinedIcon sx={{ fontSize: 14 }} />{selectedArtifacts.size}/{artifacts.length}</span>
            <button onClick={() => setSelectedArtifacts(new Set(artifacts))} disabled={!!runningHostId} style={linkButtonStyle}><SelectAllIcon sx={{ fontSize: 14 }} />전체 선택</button>
            <button onClick={() => setSelectedArtifacts(new Set())} disabled={!!runningHostId} style={linkButtonStyle}><DeselectIcon sx={{ fontSize: 14 }} />전체 해제</button>
            <button onClick={() => setArtifactListExpanded((expanded) => !expanded)} style={linkButtonStyle}>
              {artifactListExpanded ? <ExpandLessIcon sx={{ fontSize: 15 }} /> : <ExpandMoreIcon sx={{ fontSize: 15 }} />}{artifactListExpanded ? "접기" : "펼치기"}
            </button>
          </div>
          {artifactListExpanded && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))", gap: 8 }}>
              {artifacts.map((name) => {
                const isCurrent = currentArtifact === name;
                const checked = selectedArtifacts.has(name);
                return (
                  <button
                    key={name}
                    type="button"
                    aria-pressed={checked}
                    onClick={() => toggleArtifact(name)}
                    disabled={!!runningHostId}
                    style={{ display: "flex", alignItems: "center", minWidth: 0, padding: "7px 12px", border: `1px solid ${isCurrent || checked ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border-subtle)"}`, borderRadius: "var(--radius-md)", fontSize: 12.5, cursor: runningHostId ? "default" : "pointer", background: isCurrent ? "color-mix(in srgb, var(--accent) 20%, var(--bg-elevated))" : checked ? "var(--accent-subtle)" : "color-mix(in srgb, var(--bg-input) 72%, var(--bg))", color: checked ? "var(--accent)" : "var(--text-faint)", fontWeight: checked ? 650 : 500, textAlign: "left", opacity: runningHostId && !isCurrent ? 0.62 : 1 }}
                  >
                    {name}
                  </button>
                );
              })}
            </div>
          )}
        </section>
      )}

      {/* host list */}
      <section style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "0 0 10px" }}>
          <h3 style={{ margin: 0, fontSize: 13.5 }}>호스트 목록</h3>
          {hosts.length > 1 && (
            <button
              onClick={handleRunAll}
              disabled={!!runningHostId || selectedArtifacts.size === 0}
              title="이 케이스의 모든 호스트를 순서대로 파싱"
              style={{ ...primaryButtonStyle, padding: "5px 12px", fontSize: 12, opacity: !!runningHostId || selectedArtifacts.size === 0 ? 0.5 : 1 }}
            >
              <PlayArrowIcon sx={{ fontSize: 15 }} />전체 파싱 ({hosts.length})
            </button>
          )}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10, overflow: "auto", flex: 1, minHeight: 0, paddingRight: 4 }}>
          {hosts.length === 0 && (
            <div style={{ padding: 24, textAlign: "center", color: "var(--text-faint)", border: "1px dashed var(--border)", borderRadius: "var(--radius-lg)" }}>
              등록된 호스트가 없습니다. 위에서 호스트를 추가하세요.
            </div>
          )}
          {hosts.map((h) => (
            <div key={h.id} className="dfir-surface" style={{ overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "16px 18px" }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 13.5 }}>{h.name}</span>
                  <StatusPill status={h.lastRunStatus} />
                  {(h.lastRunStatus === "ok" || h.lastRunStatus === "error") && h.lastRunDurationSecs != null && (
                    <span
                      title="마지막 파싱 소요 시간"
                      style={{ fontSize: 11, fontWeight: 600, color: "var(--accent)", background: "var(--accent-subtle, var(--bg-elevated))", padding: "2px 8px", borderRadius: "var(--radius-lg)" }}
                    >
                      {formatDuration(h.lastRunDurationSecs)} 소요
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 3 }} title={h.targetDir}>
                  {h.targetDir}
                </div>
                {h.lastRunAt && <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>마지막 실행: {h.lastRunAt}</div>}
              </div>
              {confirmDeleteId === h.id ? (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 12, color: "var(--danger)" }}>분석 결과와 해당 호스트의 북마크가 삭제됩니다.</span>
                  <button onClick={() => handleDelete(h.id)} disabled={deleting} style={{ ...dangerButtonStyle, opacity: deleting ? 0.5 : 1 }}><DeleteOutlineIcon sx={{ fontSize: 15 }} />삭제</button>
                  <button onClick={() => setConfirmDeleteId(null)} disabled={deleting} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "7px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12.5 }}><CancelOutlinedIcon sx={{ fontSize: 15 }} />취소</button>
                </div>
              ) : (
                <>
                  {runningHostId === h.id ? (
                    <button onClick={handleCancel} style={dangerButtonStyle}><CancelOutlinedIcon sx={{ fontSize: 15 }} />취소</button>
                  ) : (
                    <button onClick={() => handleRun(h.id)} disabled={!!runningHostId || selectedArtifacts.size === 0} style={{ ...primaryButtonStyle, opacity: !!runningHostId || selectedArtifacts.size === 0 ? 0.5 : 1 }}>
                      <PlayArrowIcon sx={{ fontSize: 16 }} />파싱
                    </button>
                  )}
                  {(h.lastRunStatus === "ok" || h.lastRunStatus === "error") && (
                    <button onClick={() => onOpenHost(h)} style={successButtonStyle}><VisibilityOutlinedIcon sx={{ fontSize: 16 }} />결과 보기</button>
                  )}
                  <button onClick={() => setConfirmDeleteId(h.id)} disabled={!!runningHostId} title="호스트 삭제 (분석 결과만, 원본 수집 데이터는 유지)" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", padding: "7px 10px", background: "transparent", color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: runningHostId ? "default" : "pointer", fontSize: 12.5, opacity: runningHostId ? 0.4 : 1 }}><DeleteOutlineIcon sx={{ fontSize: 16 }} /></button>
                </>
              )}
            </div>
            {runningHostId === h.id && (
              <InlineParseProgress
                stepLabel={stepLabel}
                percent={percent}
                completedSteps={completedSteps}
                totalSteps={totalSteps}
              />
            )}
            {runComplete && completedHostId === h.id && failedArtifacts.length > 0 && (
              <div style={{ padding: "8px 18px 16px", color: "var(--danger)", fontSize: 12.5, fontWeight: 650 }}>
                파싱 실패: {failedArtifacts.join(", ")}
              </div>
            )}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
