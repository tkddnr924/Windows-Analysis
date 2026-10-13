"use client";
// SMB 관련 기록 (docs-09 A02/A03) — 저장된 SmbRelations로 접속 기록 아래에 관련 기록을
// 묶고, 연결되지 않은 기록(NTLM 검증·경계 등)은 단독 행으로 시간순 표시한다.
import LinkOutlinedIcon from "@mui/icons-material/LinkOutlined";
import { formatEvidenceTimestamp } from "@/lib/timeRange";
import { CONTEXT_KIND_LABELS, RELATION_LABELS, type ContextItem } from "@/lib/smbHistory";

type Row = Record<string, string>;

const KIND_COLOR: Record<string, string> = {
  access: "#f2a86f",
  ntlm_credential_validation: "var(--accent)",
  special_privileges_assigned: "var(--warning)",
  special_privileges: "var(--warning)",
  logon_instance_end: "var(--text-dim)",
  log_cleared: "var(--danger)",
};
const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)" };
const time = (value: string | undefined) => (value ? formatEvidenceTimestamp(value) : "시각 미상");
const colorOf = (kind: string) => KIND_COLOR[kind] ?? "var(--text-faint)";

function Badge({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ flexShrink: 0, minWidth: 74, textAlign: "center", fontSize: 11.5, fontWeight: 750, color, padding: "2px 8px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 15%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}

/** One timeline step inside a linked card. */
function Step({ color, label, row, last, onOpen }: { color: string; label: string; row: Row; last: boolean; onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen} title={[row.description, row.event_id && `이벤트 ${row.event_id}`, row.logon_id && `로그온 ID ${row.logon_id}`].filter(Boolean).join("\n")}
      onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
      style={{ position: "relative", width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "5px 14px 5px 38px", border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: 13 }}>
      <span aria-hidden="true" style={{ position: "absolute", left: 18, top: "50%", width: 9, height: 9, marginTop: -4.5, borderRadius: "50%", background: color, boxShadow: `0 0 0 3px color-mix(in srgb, ${color} 20%, transparent)` }} />
      {!last && <span aria-hidden="true" style={{ position: "absolute", left: 22, top: "calc(50% + 7px)", height: "calc(100% - 4px)", width: 1, background: "var(--border)" }} />}
      <Badge color={color}>{label}</Badge>
      <span style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: row.timestamp ? "var(--text-time)" : "var(--text-faint)" }}>{time(row.timestamp)}</span>
    </button>
  );
}

export default function SmbContextPanel({ items, accountText, onOpen }: {
  items: ContextItem<Row>[];
  accountText: (row: Row) => string;
  onOpen: (row: Row, table: "SmbHistory" | "SmbContext") => void;
}) {
  if (items.length === 0) return <div role="status" style={{ color: "var(--text-faint)", textAlign: "center", padding: 44, fontSize: 13 }}>기록 없음</div>;
  return (
    <div role="list" aria-label="관련 기록" style={{ display: "grid", gap: 8 }}>
      {items.map((item) => {
        if (item.kind === "linked") {
          const record = item.record;
          const account = accountText(record);
          return (
            <section role="listitem" key={item.key} aria-label="접속 연결 기록" style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderBottom: "1px solid var(--border-subtle)", fontSize: 12.5, flexWrap: "wrap" }}>
                <LinkOutlinedIcon aria-hidden="true" sx={{ fontSize: 16, color: "var(--text-faint)" }} />
                {record.remote_address && <span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{record.remote_address}</span>}
                {record.workstation_name && <span style={{ fontFamily: "var(--mono)", color: "var(--text-dim)" }}>{record.workstation_name}</span>}
                {account && <span style={{ color: "var(--text-dim)" }}>{account}</span>}
                {record.logon_id && <span title="로그온 ID" style={{ marginLeft: "auto", fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)" }}>{record.logon_id}</span>}
              </div>
              <div style={{ padding: "4px 0" }}>
                <Step color={colorOf("access")} label={record.result === "실패" ? "로그온 실패" : "로그온"} row={record} last={item.children.length === 0} onOpen={() => onOpen(record, "SmbHistory")} />
                {item.children.map((child, index) => (
                  <Step key={child.row.record_id} color={colorOf(child.relation)} label={RELATION_LABELS[child.relation] ?? CONTEXT_KIND_LABELS[child.row.event_type] ?? child.relation} row={child.row} last={index === item.children.length - 1} onOpen={() => onOpen(child.row, "SmbContext")} />
                ))}
              </div>
            </section>
          );
        }
        const row = item.row;
        const account = accountText(row);
        const color = colorOf(row.event_type);
        return (
          <button role="listitem" type="button" key={item.key} onClick={() => onOpen(row, "SmbContext")} title={[row.description, row.event_id && `이벤트 ${row.event_id}`, row.authentication_package].filter(Boolean).join("\n")}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-panel)"; }}
            style={{ display: "flex", alignItems: "center", gap: 10, minHeight: 38, padding: "6px 14px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: 12.5 }}>
            <Badge color={color}>{CONTEXT_KIND_LABELS[row.event_type] ?? row.description}</Badge>
            <span style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", width: 176, flexShrink: 0 }}>{time(row.timestamp)}</span>
            {row.workstation_name && <span style={{ fontFamily: "var(--mono)", color: "var(--text-dim)" }}>{row.workstation_name}</span>}
            {account && <span style={{ color: "var(--text-dim)" }}>{account}</span>}
            {RESULT_COLOR[row.result] && <span style={{ marginLeft: "auto", fontSize: 11.5, fontWeight: 700, color: RESULT_COLOR[row.result] }}>{row.result}</span>}
          </button>
        );
      })}
    </div>
  );
}
