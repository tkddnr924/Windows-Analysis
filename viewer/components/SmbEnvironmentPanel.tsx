"use client";
// SMB 서버 환경 (docs-09 A05) — 저장된 LanmanServer 설정·SCM 기록을 의미 중심으로
// 보여 주고, 원본 값 표는 접어서 함께 둔다.
import { useMemo, useState } from "react";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import { formatEvidenceTimestamp } from "@/lib/timeRange";
import { summarizeEnvironment, type EnvItem } from "@/lib/smbEnvironment";
import { EVIDENCE_KIND_LABELS } from "@/lib/smbHistory";

type Row = Record<string, string>;

const time = (value: string | undefined) => (value ? formatEvidenceTimestamp(value) : "");
const card: React.CSSProperties = { border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden", minWidth: 0 };
const cellStyle: React.CSSProperties = { padding: "7px 10px", borderTop: "1px solid var(--border-subtle)", fontSize: 12.5, verticalAlign: "top" };
const headStyle: React.CSSProperties = { padding: "7px 10px", fontSize: 11, fontWeight: 600, color: "var(--text-faint)", textAlign: "left", whiteSpace: "nowrap" };
const STATE_COLOR = { on: "var(--success)", off: "var(--text-faint)" } as const;

function CardHead({ title, keyTime }: { title: string; keyTime?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
      <span style={{ fontSize: 13, fontWeight: 700 }}>{title}</span>
      {keyTime && <span title="레지스트리 키 마지막 수정 시각" style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>키 수정 {time(keyTime)}</span>}
    </div>
  );
}

function Tile({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div style={{ ...card, padding: "12px 14px", display: "grid", gap: 4 }}>
      <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</span>
      <span style={{ fontSize: 20, fontWeight: 750, color: color ?? "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</span>
      {sub && <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sub}</span>}
    </div>
  );
}

function ItemRow({ item }: { item: EnvItem }) {
  const color = item.state ? STATE_COLOR[item.state] : "var(--text)";
  // Raw name/value, note and key path appear on hover only.
  const hover = [`${item.name} = ${item.raw}`, item.note, item.keyPath].filter(Boolean).join("\n");
  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(120px, 34%) minmax(0, 1fr)", gap: 10, alignItems: "baseline", padding: "8px 14px", borderTop: "1px solid var(--border-subtle)" }}>
      <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{item.label}</span>
      <span style={{ minWidth: 0 }}>
        {item.state
          ? <span title={hover} style={{ fontSize: 12, fontWeight: 750, color, padding: "1px 8px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 15%, transparent)`, cursor: "help" }}>{item.value}</span>
          : <span title={hover} style={{ fontSize: 13.5, fontWeight: 650, wordBreak: "break-all", cursor: "help" }}>{item.value}</span>}
      </span>
    </div>
  );
}

export default function SmbEnvironmentPanel({ rows }: { rows: Row[] }) {
  const summary = useMemo(() => summarizeEnvironment(rows), [rows]);
  const [showRaw, setShowRaw] = useState(false);
  const start = summary.service.find((item) => item.name.toLowerCase() === "start");
  const differing = summary.otherSets.filter((set) => set.differences.length > 0);

  if (rows.length === 0) return <div role="status" style={{ color: "var(--text-faint)", textAlign: "center", padding: 44, fontSize: 13 }}>기록 없음</div>;

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
        {summary.lastState && <Tile label="서버 서비스 마지막 상태" value={summary.lastState.text} sub={`${time(summary.lastState.time)} · ${summary.lastState.eventId}`} color={summary.lastState.text === "실행" ? "var(--success)" : undefined} />}
        {start && <Tile label="시작 유형" value={start.value} />}
        <Tile label="등록 공유 폴더" value={`${summary.shares.length}개`} sub={summary.shares.map((share) => share.name).join(", ") || undefined} />
        {summary.activeSet && <Tile label="현재 ControlSet" value={summary.activeSet} sub={summary.otherSets.map((set) => `${set.set} ${set.differences.length ? `차이 ${set.differences.length}` : "동일"}`).join(" · ") || undefined} />}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: 12, alignItems: "start" }}>
        {(summary.service.length > 0 || summary.events.length > 0) && (
          <section aria-label="서버 서비스" style={card}>
            <CardHead title="서버 서비스 (LanmanServer)" keyTime={summary.serviceKeyTime} />
            {summary.service.map((item) => <ItemRow key={item.name} item={item} />)}
            {summary.events.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: "minmax(120px, 34%) minmax(0, 1fr)", gap: 10, padding: "10px 14px 12px", borderTop: "1px solid var(--border-subtle)" }}>
                <span style={{ fontSize: 12, color: "var(--text-dim)" }}>상태 기록</span>
                <ol aria-label="서비스 상태 기록" style={{ listStyle: "none", margin: 0, padding: 0 }}>
                  {summary.events.map((event, index) => {
                    const color = event.kind === "service_state" ? (event.text === "실행" ? "var(--success)" : "var(--text-dim)") : "var(--accent)";
                    const last = index === summary.events.length - 1;
                    return (
                      <li key={`${event.time}-${index}`} title={`이벤트 ${event.eventId}`} style={{ position: "relative", display: "flex", alignItems: "center", gap: 10, paddingLeft: 20, paddingBottom: last ? 0 : 12 }}>
                        <span aria-hidden="true" style={{ position: "absolute", left: 4, top: 6, width: 9, height: 9, borderRadius: "50%", background: color, boxShadow: `0 0 0 3px color-mix(in srgb, ${color} 20%, transparent)` }} />
                        {!last && <span aria-hidden="true" style={{ position: "absolute", left: 8, top: 17, bottom: 0, width: 1, background: "var(--border)" }} />}
                        <span style={{ fontSize: 12, fontWeight: 750, color, padding: "1px 8px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 15%, transparent)`, cursor: "help" }}>{event.text}</span>
                        <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-time)" }}>{time(event.time)}</span>
                      </li>
                    );
                  })}
                </ol>
              </div>
            )}
          </section>
        )}

        <div style={{ display: "grid", gap: 12 }}>
          <section aria-label="공유 폴더" style={card}>
            <CardHead title="공유 폴더" keyTime={summary.sharesKeyTime} />
            {summary.shares.length === 0
              ? <div style={{ padding: "12px 14px", fontSize: 13, color: "var(--text-dim)" }}>등록된 공유 없음</div>
              : summary.shares.map((share) => (
                <div key={share.name} style={{ display: "flex", alignItems: "baseline", gap: 10, padding: "8px 14px", borderTop: "1px solid var(--border-subtle)", flexWrap: "wrap" }}>
                  <span style={{ fontSize: 13.5, fontWeight: 700 }}>{share.name}</span>
                  {share.path && <span style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text-dim)", wordBreak: "break-all" }}>{share.path}</span>}
                  {share.remark && <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{share.remark}</span>}
                  {share.type && <span style={{ marginLeft: "auto", fontSize: 11.5, fontWeight: 700, color: "var(--accent)" }}>{share.type}</span>}
                </div>
              ))}
          </section>

          {summary.security.length > 0 && (
            <section aria-label="보안 · 연결 설정" style={card}>
              <CardHead title="보안 · 연결 설정" keyTime={summary.parametersKeyTime} />
              {summary.security.map((item) => <ItemRow key={item.name} item={item} />)}
            </section>
          )}

          {differing.length > 0 && (
            <section aria-label="ControlSet 차이" style={card}>
              <CardHead title={`${summary.activeSet}와 다른 값`} />
              {differing.flatMap((set) => set.differences.map((difference) => (
                <div key={`${set.set}-${difference.name}`} style={{ display: "flex", gap: 10, alignItems: "baseline", padding: "7px 14px", borderTop: "1px solid var(--border-subtle)", fontSize: 12.5, fontFamily: "var(--mono)", flexWrap: "wrap" }}>
                  <span style={{ color: "var(--text-dim)" }}>{set.set}</span>
                  <span style={{ fontWeight: 700 }}>{difference.name}</span>
                  <span>{difference.active || "(없음)"} → {difference.other || "(없음)"}</span>
                </div>
              )))}
            </section>
          )}
        </div>
      </div>

      <section style={card}>
        <button type="button" aria-expanded={showRaw} onClick={() => setShowRaw((open) => !open)}
          style={{ width: "100%", display: "flex", alignItems: "center", gap: 6, padding: "9px 14px", border: "none", background: "transparent", color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5, fontWeight: 650, textAlign: "left" }}>
          <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, transform: showRaw ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
          원본 값 {rows.length.toLocaleString()}
        </button>
        {showRaw && (
          <table aria-label="환경 원본 값" style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}>
            <thead><tr>
              <th style={{ ...headStyle, width: 190 }}>시각</th>
              <th style={{ ...headStyle, width: 110 }}>종류</th>
              <th style={headStyle}>대상</th>
              <th style={headStyle}>값</th>
            </tr></thead>
            <tbody>
              {rows.map((row) => {
                const target = row.service_name || [row.key_path, row.value_name].filter(Boolean).join(" \\ ");
                const value = row.state || [row.start_type_before, row.start_type_after].filter(Boolean).join(" → ") || row.value_data || row.value_data_hex || "";
                return (
                  <tr key={row.environment_id}>
                    <td style={{ ...cellStyle, fontFamily: "var(--mono)", color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", whiteSpace: "nowrap" }} title={row.timestamp_kind}>{time(row.timestamp)}</td>
                    <td style={cellStyle}>{EVIDENCE_KIND_LABELS[row.evidence_kind] ?? row.evidence_kind}</td>
                    <td title={target} style={{ ...cellStyle, fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{target}</td>
                    <td title={value} style={{ ...cellStyle, fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
