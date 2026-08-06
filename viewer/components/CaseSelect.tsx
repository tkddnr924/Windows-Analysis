"use client";

import { useState } from "react";
import type { Case } from "@/lib/types";

interface CaseSelectProps {
  cases: Case[];
  casesError: string | null;
  onOpen: (c: Case) => void;
  onChanged: () => void;
}

// The first screen: pick or create a CASE (an incident). A case holds one or
// more hosts (collected machines) — you drill into a case to add/parse/browse
// its hosts.
export default function CaseSelect({ cases, casesError, onOpen, onChanged }: CaseSelectProps) {
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function handleCreate() {
    if (!newName.trim()) return;
    setCreating(true);
    try {
      const c = await window.api.createCase(newName.trim());
      setNewName("");
      onChanged();
      onOpen(c);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(caseId: string) {
    setDeleting(true);
    try {
      await window.api.deleteCase(caseId);
      onChanged();
    } finally {
      setDeleting(false);
      setConfirmDeleteId(null);
    }
  }

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 24, maxWidth: 860, margin: "0 auto", width: "100%" }}>
      <h2 style={{ fontSize: 18, fontWeight: 700, margin: "4px 0 4px" }}>🗂️ 케이스</h2>
      <div style={{ fontSize: 12.5, color: "var(--text-dim)", marginBottom: 20 }}>
        사고(케이스)를 선택하거나 새로 만드세요. 케이스 안에 분석할 호스트(수집한 장비)를 추가합니다.
      </div>

      <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 18, boxShadow: "var(--shadow-card)", marginBottom: 22 }}>
        <h3 style={{ margin: "0 0 12px", fontSize: 13.5 }}>새 케이스 생성</h3>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <input
            placeholder="케이스 이름 (예: INCIDENT-2026-08)"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleCreate()}
            style={{ flex: 1, padding: "8px 11px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", fontSize: 13 }}
          />
          <button
            onClick={handleCreate}
            disabled={creating || !newName.trim()}
            style={{ padding: "8px 18px", background: "var(--accent-emphasis)", color: "#fff", fontWeight: 600, border: "none", borderRadius: "var(--radius-md)", cursor: creating || !newName.trim() ? "default" : "pointer", fontSize: 13, opacity: creating || !newName.trim() ? 0.5 : 1, whiteSpace: "nowrap" }}
          >
            케이스 생성
          </button>
        </div>
      </section>

      {casesError && (
        <div style={{ padding: 14, marginBottom: 16, border: "1px solid var(--danger)", background: "var(--danger-subtle)", borderRadius: "var(--radius-md)", color: "var(--danger)", fontSize: 12.5, whiteSpace: "pre-wrap" }}>
          케이스 목록을 불러오지 못했습니다:{"\n"}{casesError}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {cases.length === 0 && !casesError && (
          <div style={{ padding: 28, textAlign: "center", color: "var(--text-faint)", border: "1px dashed var(--border)", borderRadius: "var(--radius-lg)" }}>
            아직 케이스가 없습니다. 위에서 새 케이스를 만들어 보세요.
          </div>
        )}
        {cases.map((c) => (
          <div
            key={c.id}
            onClick={() => onOpen(c)}
            style={{ display: "flex", alignItems: "center", gap: 12, padding: "16px 18px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", cursor: "pointer" }}
            onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
            onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
          >
            <span style={{ fontSize: 20 }}>🗂️</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 700, fontSize: 14 }}>{c.name}</div>
              <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 3 }}>
                호스트 {c.hosts.length}개 · 생성 {c.createdAt}
              </div>
            </div>
            {confirmDeleteId === c.id ? (
              <div onClick={(e) => e.stopPropagation()} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 12, color: "var(--danger)" }}>케이스 전체 삭제?</span>
                <button onClick={() => handleDelete(c.id)} disabled={deleting} style={{ padding: "6px 12px", background: "transparent", color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12 }}>삭제</button>
                <button onClick={() => setConfirmDeleteId(null)} disabled={deleting} style={{ padding: "6px 12px", background: "var(--bg-elevated)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12 }}>취소</button>
              </div>
            ) : (
              <button
                onClick={(e) => { e.stopPropagation(); setConfirmDeleteId(c.id); }}
                title="케이스 삭제 (모든 호스트 분석 결과 포함)"
                style={{ padding: "6px 10px", background: "transparent", color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12.5 }}
              >
                🗑
              </button>
            )}
            <span style={{ color: "var(--text-faint)", fontSize: 18 }}>›</span>
          </div>
        ))}
      </div>
    </div>
  );
}
