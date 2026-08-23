"use client";

import CircularProgress from "@mui/material/CircularProgress";
import CloseIcon from "@mui/icons-material/Close";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import TaskAltIcon from "@mui/icons-material/TaskAlt";

interface Props {
  hostName: string;
  stepLabel: string;
  percent: number;
  complete: boolean;
  hadError: boolean;
  runningCount: number;
  queuedCount: number;
  /** Jump to the parsing screen (undefined = no navigation available here). */
  onOpen?: () => void;
  onDismiss: () => void;
}

// A slim always-on-top bar so an in-progress (or just-finished) parse stays
// visible after the user navigates away from the RunPipeline screen.
export default function GlobalProgress({ hostName, stepLabel, percent, complete, hadError, runningCount, queuedCount, onOpen, onDismiss }: Props) {
  const liveCount = runningCount + queuedCount;
  const hasLiveRuns = liveCount > 0;
  const color = hasLiveRuns ? "var(--accent)" : hadError ? "var(--danger)" : complete ? "var(--success)" : "var(--accent)";
  const stateIcon = hasLiveRuns
    ? <CircularProgress size={18} thickness={4.5} aria-label="파싱 진행 중" sx={{ color }} />
    : complete
    ? hadError
      ? <ReportProblemOutlinedIcon sx={{ fontSize: 18, color }} />
      : <TaskAltIcon sx={{ fontSize: 18, color }} />
    : <CircularProgress size={18} thickness={4.5} aria-label="파싱 진행 중" sx={{ color }} />;
  return (
    <div
      style={{
        position: "fixed",
        left: "50%",
        bottom: 16,
        transform: "translateX(-50%)",
        zIndex: 1000,
        minWidth: 360,
        maxWidth: "90vw",
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow-panel)",
        padding: "10px 14px",
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", flexShrink: 0 }}>{stateIcon}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div role="status" aria-live="polite" aria-atomic="true" style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12.5, fontWeight: 700, color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            <DesktopWindowsOutlinedIcon sx={{ fontSize: 15, color: "var(--text-dim)", flexShrink: 0 }} />
            <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{hasLiveRuns ? `실행 ${runningCount}개 · 대기 ${queuedCount}개` : hostName || "호스트"}</span>
            <span style={{ color: "var(--text-faint)", fontWeight: 400, flexShrink: 0 }}>· {hasLiveRuns && liveCount > 1 ? "진행 화면에서 호스트별 상태 확인" : stepLabel}</span>
          </div>
        </div>
        {!hasLiveRuns || liveCount === 1 ? <span style={{ fontSize: 15, fontWeight: 700, fontVariantNumeric: "tabular-nums", color }}>{percent}%</span> : null}
        {onOpen && (
          <button type="button" onClick={onOpen} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, fontWeight: 600, padding: "3px 9px", background: "var(--accent-subtle)", color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-md)", cursor: "pointer", whiteSpace: "nowrap" }}>
            <OpenInNewIcon sx={{ fontSize: 14 }} />진행 화면으로
          </button>
        )}
        <button type="button" onClick={onDismiss} title="알림 닫기" aria-label="진행 알림 닫기" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", padding: 2, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}>
            <CloseIcon sx={{ fontSize: 16 }} />
        </button>
      </div>
      {(!hasLiveRuns || liveCount === 1) && <div style={{ height: 5, background: "var(--bg)", borderRadius: 999, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${percent}%`, background: color, borderRadius: 999, transition: "width 0.3s ease" }} />
      </div>}
    </div>
  );
}
