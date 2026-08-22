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
    <div className="dfir-view case-launcher" style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
      <header className="case-launcher__intro">
        <div>
          <p>Windows Forensics</p>
          <h1>분석 케이스</h1>
        </div>
      </header>

      {casesError && (
        <div className="case-launcher__error">
          케이스 목록을 불러오지 못했습니다.<br />{casesError}
        </div>
      )}

      <div className="case-launcher__content">
        <section className="case-create" aria-labelledby="new-case-title">
          <div className="case-create__heading">
            <h2 id="new-case-title">새 케이스 만들기</h2>
          </div>
          <div className="case-create__form">
            <label htmlFor="new-case-name">케이스 이름</label>
            <div>
              <input
                id="new-case-name"
                placeholder="예: INCIDENT-2026-08"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              />
              <button onClick={handleCreate} disabled={creating || !newName.trim()}>
                케이스 만들기
              </button>
            </div>
          </div>
        </section>

        <section className="case-list" aria-label="케이스 목록">
          <div className="case-list__header">
            <span>케이스 {cases.length}개</span>
          </div>

          {cases.length === 0 && !casesError && (
            <div className="case-list__empty">
              저장된 케이스가 없습니다. 왼쪽에서 첫 케이스를 만드세요.
            </div>
          )}

          <div className="case-list__items">
            {cases.map((c) => (
              <article key={c.id} className="case-row" onClick={() => onOpen(c)}>
                <div className="case-row__primary">
                  <h3>{c.name}</h3>
                  <p>호스트 {c.hosts.length}개 <span /> 생성 {c.createdAt}</p>
                </div>
                {confirmDeleteId === c.id ? (
                  <div className="case-row__confirm" onClick={(e) => e.stopPropagation()}>
                    <span>이 케이스와 분석 결과를 삭제할까요?</span>
                    <button className="case-row__delete" onClick={() => handleDelete(c.id)} disabled={deleting}>삭제</button>
                    <button className="case-row__cancel" onClick={() => setConfirmDeleteId(null)} disabled={deleting}>취소</button>
                  </div>
                ) : (
                  <div className="case-row__actions" onClick={(e) => e.stopPropagation()}>
                    <button onClick={() => onOpen(c)}>열기</button>
                    <button className="case-row__remove" onClick={() => setConfirmDeleteId(c.id)} title="케이스 삭제">삭제</button>
                  </div>
                )}
              </article>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
