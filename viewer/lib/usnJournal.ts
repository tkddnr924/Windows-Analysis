// USN journal view helpers (docs-05). Only stored values are labelled; nothing
// is inferred. No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;
interface RenameLike {
  event: Cells;
  candidates: Cells[];
}
interface GroupLike {
  group: Cells;
  members: Cells[];
  renames: RenameLike[];
}

/** Stored rename pair first, then a name change inside the group, else the last name.
 *  A side without a single stored name shows its candidate count, never a pick. */
export function groupHeadline(entry: GroupLike): string {
  const rename = entry.renames[0];
  if (rename) {
    const side = (name: string | undefined, role: "old" | "new", label: string) => {
      if (name) return name;
      const count = rename.candidates.filter((c) => c.role === role || c.role === "both").length;
      return count > 1 ? `${label} 후보 ${count}개` : "?";
    };
    return `${side(rename.event.old_file_name, "old", "이전 이름")} → ${side(rename.event.new_file_name, "new", "새 이름")}`;
  }
  const first = entry.group.first_file_name || "";
  const last = entry.group.last_file_name || "";
  if (Number(entry.group.distinct_file_name_count) > 1 && first && last && first !== last) return `${first} → ${last}`;
  return last || first || "(이름 없음)";
}

export interface SideCandidate {
  candidate: Cells;
  /** The stored representative link of the event (old/new_record_id). */
  representative: boolean;
}

/** Candidates per side ("both" belongs to each); the stored representative is flagged. */
export function candidateSides(rename: RenameLike): { old: SideCandidate[]; new: SideCandidate[] } {
  const side = (role: "old" | "new", representative: string | undefined) =>
    rename.candidates
      .filter((c) => c.role === role || c.role === "both")
      .map((candidate) => ({ candidate, representative: Boolean(representative) && candidate.record_id === representative }));
  return { old: side("old", rename.event.old_record_id), new: side("new", rename.event.new_record_id) };
}

const RENAME_STATUS: Record<string, string> = {
  paired: "짝 확인",
  missing_old: "이전 이름 없음",
  missing_new: "새 이름 없음",
  ambiguous: "모호",
};

export function renameStatusLabel(status: string | undefined): string {
  return (status && RENAME_STATUS[status]) || status || "";
}

// Reasons written by the core rename linker (rust/core derived/usn.rs).
const AMBIGUITY: Record<string, string> = {
  multiple_old_names: "이전 이름이 여러 개",
  multiple_new_names: "새 이름이 여러 개",
  multiple_old_parents: "이전 이름의 부모 참조가 서로 다름",
  multiple_new_parents: "새 이름의 부모 참조가 서로 다름",
  usn_missing: "USN 없는 후보 있음",
  file_reference_missing: "파일 참조 없음",
  usn_order_unresolved: "OLD/NEW USN 순서를 정할 수 없음",
};

export function ambiguityLabels(reason: string | undefined): string[] {
  return (reason ?? "").split(/[,|;]/).map((part) => part.trim()).filter(Boolean).map((part) => AMBIGUITY[part] ?? part);
}

export function reasonFlags(reason: string | undefined): string[] {
  return (reason ?? "").split("|").map((flag) => flag.trim()).filter(Boolean);
}

export function matchedCount(entry: GroupLike): number {
  return entry.members.filter((member) => member.__matched === "true").length;
}
