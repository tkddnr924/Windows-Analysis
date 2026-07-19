"use client";

import { useState } from "react";
import type { ProjectRootStatus } from "@/lib/types";

interface ProjectRootSetupProps {
  status: ProjectRootStatus;
  onConfigured: (status: ProjectRootStatus) => void;
}

export default function ProjectRootSetup({ status, onConfigured }: ProjectRootSetupProps) {
  const [lastAttempt, setLastAttempt] = useState<ProjectRootStatus | null>(null);

  async function pick() {
    const result = await window.api.pickProjectRoot();
    if (!result) return;
    setLastAttempt(result);
    if (result.valid) onConfigured(result);
  }

  const failed = lastAttempt && !lastAttempt.valid ? lastAttempt : null;

  return (
    <main
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: 16,
        padding: 24,
        textAlign: "center",
      }}
    >
      <span style={{ fontSize: 40 }}>📁</span>
      <div style={{ fontSize: 15, fontWeight: 700 }}>Windows-Analysis 프로젝트 폴더를 선택하세요</div>
      <div style={{ fontSize: 12.5, color: "var(--text-dim)", maxWidth: 440, lineHeight: 1.6 }}>
        이 앱은 파싱 파이프라인(main.py, venv)과 케이스 데이터를 찾기 위해 실제 Windows-Analysis 프로젝트
        폴더 위치가 필요합니다. 아래 버튼으로 <code style={{ fontFamily: "var(--mono)" }}>main.py</code>가 있는
        폴더를 선택해 주세요.
      </div>
      <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>
        현재 설정된 경로: {status.root}
      </div>
      {failed && (
        <div style={{ fontSize: 12, color: "var(--danger)", maxWidth: 440 }}>
          선택한 폴더에서 main.py를 찾을 수 없습니다: {failed.root}
        </div>
      )}
      <button
        onClick={pick}
        style={{
          padding: "8px 18px",
          background: "var(--accent)",
          color: "#0d1117",
          border: "none",
          borderRadius: "var(--radius-md)",
          cursor: "pointer",
          fontWeight: 700,
          fontSize: 13,
        }}
      >
        폴더 선택...
      </button>
    </main>
  );
}
