"use client";

import { Fragment, useEffect, useId, useRef, useState } from "react";
import type { MftListOptions } from "@/lib/types";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import { useModalDialog } from "@/lib/useModalDialog";
import {
  AROUND_PRESETS, DEFAULT_LIST_FILTERS, EXTENSION_PRESETS, MFT_TIME_FIELDS, NOISE_FOLDERS, SIZE_PRESETS,
  activityOf, noiseExcluded, presetActive, timeBounds, timeFieldsLabel, timeKeysFor, toListOptions,
  withNoiseExcluded, withTimeKeys, withTimeMode,
  type Activity, type ExtensionPreset, type ListFilters, type SizePreset, type TimeMode,
} from "@/lib/mftListFilters";

type Row = Record<string, string>;

export function Segmented<T extends string>({ label, options, value, onChange, stretch = false }: { label: string; options: { value: T; label: string; title?: string }[]; value: T | null; onChange: (value: T) => void; stretch?: boolean }) {
  return (
    <span role="group" aria-label={label} style={{ display: stretch ? "flex" : "inline-flex", gap: 2, padding: 3, borderRadius: 9, background: "var(--bg-input, var(--bg-elevated))", border: "1px solid var(--border-subtle)" }}>
      {options.map((option) => {
        const active = option.value === value;
        return <button key={option.value} type="button" aria-pressed={active} title={option.title} onClick={() => onChange(option.value)} style={{ flex: stretch ? "1 1 0" : undefined, minHeight: 28, padding: "0 12px", fontSize: 12.5, fontWeight: active ? 650 : 500, border: "none", borderRadius: 6, cursor: "pointer", whiteSpace: "nowrap", transition: "background 120ms, color 120ms", background: active ? "var(--bg-panel)" : "transparent", boxShadow: active ? "0 1px 2px rgba(0,0,0,0.35), inset 0 0 0 1px var(--border)" : "none", color: active ? "var(--text)" : "var(--text-dim)" }}>{option.label}</button>;
      })}
    </span>
  );
}

function Switch({ on, onChange, label, hint }: { on: boolean; onChange: (on: boolean) => void; label: string; hint?: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} onClick={() => onChange(!on)} style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
      <span aria-hidden="true" style={{ position: "relative", flexShrink: 0, width: 30, height: 18, borderRadius: 999, background: on ? "var(--accent)" : "var(--border)", transition: "background 120ms" }}>
        <span style={{ position: "absolute", top: 2, left: on ? 14 : 2, width: 14, height: 14, borderRadius: "50%", background: "#fff", transition: "left 120ms" }} />
      </span>
      <span style={{ display: "grid", gap: 1 }}>
        <span style={{ fontSize: 12.5 }}>{label}</span>
        {hint && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{hint}</span>}
      </span>
    </button>
  );
}

// Unlabelled visual group; the title stays only for screen readers.
function Step({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section aria-label={title} style={{ display: "grid", gap: 12, minWidth: 0, padding: "18px 22px" }}>
      {children}
    </section>
  );
}

const TIME_MODES: { value: TimeMode; label: string }[] = [
  { value: "all", label: "전체 기간" },
  { value: "around", label: "특정 시각 전후" },
  { value: "range", label: "기간 지정" },
];
const ACTIVITIES: { value: Activity; label: string }[] = [
  { value: "created", label: "생성" },
  { value: "modified", label: "수정" },
  { value: "both", label: "생성 또는 수정" },
];
const TIME_GRID = [
  { label: "생성", si: "created", fn: "fn_created" },
  { label: "수정", si: "modified", fn: "fn_modified" },
  { label: "MFT 수정", si: "mft_modified", fn: "fn_mft_modified" },
  { label: "접근", si: "accessed", fn: "fn_accessed" },
];

/**
 * Filter dialog of the recursive file list (docs-04 §3), laid out as three
 * steps — when, where, which files — with everything else under 「추가 조건」.
 * The draft is applied only with 「적용」 and never while the time is invalid.
 */
export default function MftListFilterModal({ filters, anchorRow, countFor, onApply, onClose }: {
  filters: ListFilters;
  /** Selected record — its stored times can become the anchor. */
  anchorRow: Row | null;
  /** Expected result count for a draft (same query as the list). */
  countFor: (options: MftListOptions) => Promise<number>;
  onApply: (next: ListFilters) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<ListFilters>(filters);
  const [customExtension, setCustomExtension] = useState(() => Boolean(filters.extension.trim()) && !(Object.keys(EXTENSION_PRESETS) as ExtensionPreset[]).some((p) => presetActive(filters, p)));
  const [excludeInput, setExcludeInput] = useState("");
  const [count, setCount] = useState<{ value: number | null; loading: boolean; failed: boolean }>({ value: null, loading: true, failed: false });
  const countSeq = useRef(0);
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);
  const set = <K extends keyof ListFilters>(key: K, value: ListFilters[K]) => setDraft((previous) => ({ ...previous, [key]: value }));

  const bounds = timeBounds(draft);
  const activity = activityOf(draft.timeKeys);
  const customExcludes = draft.excludePaths.filter((path) => !NOISE_FOLDERS.includes(path));
  const advancedCount = [
    draft.pattern.trim(), customExcludes.length, draft.kind !== DEFAULT_LIST_FILTERS.kind, draft.inUse !== "all", draft.size !== "all",
    draft.pathIncomplete, draft.residentOnly, draft.siBeforeFn, draft.timeMode !== "all" && !activity,
  ].filter(Boolean).length;
  const [advanced, setAdvanced] = useState(advancedCount > 0);
  const optionsKey = JSON.stringify(toListOptions(draft, undefined));

  // Live expected count; stale answers are dropped.
  useEffect(() => {
    if (bounds.error) return;
    const seq = ++countSeq.current;
    setCount((previous) => ({ ...previous, loading: true, failed: false }));
    const timer = window.setTimeout(() => {
      countFor(JSON.parse(optionsKey) as MftListOptions)
        .then((value) => { if (countSeq.current === seq) setCount({ value, loading: false, failed: false }); })
        .catch(() => { if (countSeq.current === seq) setCount({ value: null, loading: false, failed: true }); });
    }, 300);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [optionsKey, bounds.error]);

  const extensionChoice: ExtensionPreset | "all" | "custom" = customExtension ? "custom" : !draft.extension.trim() ? "all" : (Object.keys(EXTENSION_PRESETS) as ExtensionPreset[]).find((p) => presetActive(draft, p)) ?? "custom";
  const chooseExtension = (choice: ExtensionPreset | "all" | "custom") => {
    setCustomExtension(choice === "custom");
    if (choice === "all") set("extension", "");
    else if (choice !== "custom") set("extension", EXTENSION_PRESETS[choice].extensions.join(", "));
  };
  const anchorTimes = anchorRow ? Object.entries(MFT_TIME_FIELDS).map(([key, spec]) => ({ key, label: spec.short, value: anchorRow[spec.column] ?? "" })).filter((t) => t.value) : [];
  const addExclude = () => {
    const value = excludeInput.trim();
    if (value && !draft.excludePaths.includes(value)) set("excludePaths", [...draft.excludePaths, value]);
    setExcludeInput("");
  };

  const control: React.CSSProperties = { height: 34, padding: "0 11px", fontSize: 12.5, background: "var(--bg-input, var(--bg-elevated))", border: "1px solid var(--border)", borderRadius: 8, color: "var(--text)", outline: "none", minWidth: 0, width: "100%", boxSizing: "border-box" };
  const mono: React.CSSProperties = { ...control, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums" };
  const label: React.CSSProperties = { fontSize: 11.5, color: "var(--text-dim)" };
  const hint: React.CSSProperties = { fontSize: 11.5, color: "var(--text-faint)", lineHeight: 1.5, margin: 0 };
  const chip = (active: boolean): React.CSSProperties => ({ height: 28, padding: "0 12px", fontSize: 12, fontWeight: active ? 600 : 500, borderRadius: 999, cursor: "pointer", whiteSpace: "nowrap", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", transition: "all 120ms" });
  const ghost: React.CSSProperties = { height: 34, padding: "0 14px", fontSize: 12.5, border: "none", borderRadius: 8, background: "transparent", color: "var(--text-dim)", cursor: "pointer" };
  const divider = <div aria-hidden="true" style={{ height: 1, margin: "0 22px", background: "var(--border-subtle)" }} />;
  const minuteSelect = (key: "aroundBefore" | "aroundAfter", text: string) => (
    <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <span style={label}>{text}</span>
      <select value={draft[key]} onChange={(event) => set(key, Number(event.target.value))} aria-label={`${text} 범위`} style={{ ...control, width: 96 }}>
        {AROUND_PRESETS.map((p) => <option key={p.minutes} value={p.minutes}>{p.label}</option>)}
        {!AROUND_PRESETS.some((p) => p.minutes === draft[key]) && <option value={draft[key]}>{draft[key]}분</option>}
      </select>
    </label>
  );

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.72)", backdropFilter: "blur(2px)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 24 }}>
      <div ref={dialogRef} onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} style={{ width: "min(620px, 96vw)", maxHeight: "90vh", display: "flex", flexDirection: "column", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 14, boxShadow: "0 24px 64px rgba(0,0,0,0.55)", overflow: "hidden" }}>
        <header style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "18px 22px 6px" }}>
          <div style={{ display: "grid", gap: 3 }}>
            <strong id={titleId} style={{ fontSize: 16, fontWeight: 650 }}>필터</strong>
            <span style={hint}>시간, 위치, 파일 유형으로 좁혀 봅니다.</span>
          </div>
          <button type="button" onClick={onClose} aria-label="필터 닫기" title="닫기 (Esc)" style={{ ...ghost, marginLeft: "auto", width: 32, height: 32, padding: 0, display: "grid", placeItems: "center" }}><CloseOutlinedIcon sx={{ fontSize: 18 }} /></button>
        </header>

        <div style={{ overflow: "auto", minHeight: 0 }}>
          <Step title="언제">
            <Segmented stretch label="기간 방식" options={TIME_MODES} value={draft.timeMode} onChange={(mode) => setDraft((previous) => withTimeMode(previous, mode))} />

            {draft.timeMode === "around" && (
              <div style={{ display: "grid", gap: 10 }}>
                {anchorRow && anchorTimes.length > 0 ? (
                  <div style={{ display: "grid", gap: 6 }}>
                    <span style={label}>기준 — 선택한 <strong style={{ color: "var(--text)", fontWeight: 600 }}>{anchorRow.file_name || "레코드"}</strong>의 시각</span>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }} role="group" aria-label="기준 레코드 시각">
                      {anchorTimes.map((t) => {
                        const active = t.value === draft.anchor.trim();
                        return <button key={t.key} type="button" aria-pressed={active} onClick={() => set("anchor", t.value)} title={t.value} style={{ ...chip(active), display: "inline-flex", alignItems: "center", gap: 6 }}><span>{t.label}</span><span style={{ fontFamily: "var(--mono)", fontSize: 11, opacity: 0.8 }}>{t.value.slice(0, 19)}</span></button>;
                      })}
                    </div>
                  </div>
                ) : <p style={hint}>목록에서 파일을 먼저 선택하면 그 파일의 시각을 기준으로 바로 쓸 수 있습니다.</p>}
                <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
                  <input value={draft.anchor} onChange={(event) => set("anchor", event.target.value)} placeholder="기준 시각 YYYY-MM-DD HH:MM:SS" aria-label="기준 시각" style={{ ...mono, flex: "1 1 220px", width: "auto" }} />
                  {minuteSelect("aroundBefore", "앞")}
                  {minuteSelect("aroundAfter", "뒤")}
                </div>
              </div>
            )}

            {draft.timeMode === "range" && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr", alignItems: "center", gap: 8 }}>
                <input value={draft.timeFrom} onChange={(event) => set("timeFrom", event.target.value)} placeholder="시작 (비우면 처음부터)" aria-label="시작 시각" style={mono} />
                <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>→</span>
                <input value={draft.timeTo} onChange={(event) => set("timeTo", event.target.value)} placeholder="끝 (비우면 끝까지)" aria-label="끝 시각" style={mono} />
              </div>
            )}

            {draft.timeMode !== "all" && <>
              <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
                <Segmented label="볼 활동" options={ACTIVITIES} value={activity?.activity ?? null} onChange={(value) => setDraft((previous) => withTimeKeys(previous, timeKeysFor(value, activityOf(previous.timeKeys)?.withFn ?? true)))} />
                <span style={{ flex: "1 1 180px" }}>
                  <Switch on={activity?.withFn ?? draft.timeKeys.some((k) => k.startsWith("fn_"))} onChange={(on) => setDraft((previous) => withTimeKeys(previous, timeKeysFor(activityOf(previous.timeKeys)?.activity ?? "created", on)))} label="$FN 시각도 확인" hint="SI가 조작돼도 FN으로 걸립니다" />
                </span>
              </div>
              {!activity && <p style={hint}>직접 고른 시각: {timeFieldsLabel(draft.timeKeys)} — 「추가 조건」에서 바꿀 수 있습니다.</p>}
              <div role={bounds.error ? "alert" : "status"} style={{ fontSize: 11.5, fontFamily: bounds.error ? undefined : "var(--mono)", color: bounds.error ? "var(--danger)" : "var(--text-faint)" }}>
                {bounds.error ?? `${bounds.start ?? "처음"}  →  ${bounds.end ?? "끝"}`}
              </div>
            </>}
          </Step>
          {divider}

          <Step title="어디서">
            <input value={draft.pathPrefix} onChange={(event) => set("pathPrefix", event.target.value)} placeholder="모든 폴더 — 특정 폴더만 보려면 예: \Users\Administrator" aria-label="포함 폴더" title="이 폴더와 그 하위만 (드라이브 문자는 무시)" style={mono} />
            <Switch on={noiseExcluded(draft)} onChange={(on) => setDraft((previous) => withNoiseExcluded(previous, on))} label="Windows 업데이트 폴더 제외" hint="WinSxS · servicing · SoftwareDistribution — 업데이트 때 대량으로 바뀌어 다른 흔적을 가립니다" />
          </Step>
          {divider}

          <Step title="어떤 파일">
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }} role="group" aria-label="파일 유형">
              <button type="button" aria-pressed={extensionChoice === "all"} onClick={() => chooseExtension("all")} style={chip(extensionChoice === "all")}>모든 파일</button>
              {(Object.keys(EXTENSION_PRESETS) as ExtensionPreset[]).map((preset) => (
                <button key={preset} type="button" aria-pressed={extensionChoice === preset} title={EXTENSION_PRESETS[preset].extensions.join(", ")} onClick={() => chooseExtension(preset)} style={chip(extensionChoice === preset)}>{EXTENSION_PRESETS[preset].label}</button>
              ))}
              <button type="button" aria-pressed={extensionChoice === "custom"} onClick={() => chooseExtension("custom")} style={chip(extensionChoice === "custom")}>확장자 직접 입력</button>
            </div>
            {extensionChoice === "custom" && <input autoFocus value={draft.extension} onChange={(event) => set("extension", event.target.value)} placeholder="exe, dll, ps1" aria-label="확장자" style={control} />}
          </Step>

          <div style={{ padding: "4px 22px 18px" }}>
            <button type="button" aria-expanded={advanced} onClick={() => setAdvanced((open) => !open)} style={{ display: "flex", alignItems: "center", gap: 6, width: "100%", height: 36, padding: "0 12px", border: "1px solid var(--border-subtle)", borderRadius: 8, background: "transparent", color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5 }}>
              <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 18, transform: advanced ? "rotate(180deg)" : "none", transition: "transform 150ms" }} />
              추가 조건
              {advancedCount > 0 && <span style={{ marginLeft: 4, padding: "1px 7px", borderRadius: 999, fontSize: 11, background: "var(--accent-subtle)", color: "var(--accent)" }}>{advancedCount}</span>}
              <span style={{ marginLeft: "auto", fontSize: 11.5, color: "var(--text-faint)" }}>이름 · 제외 폴더 · 레코드 · 크기 · 정렬</span>
            </button>
            {advanced && (
              <div style={{ display: "grid", gridTemplateColumns: "96px minmax(0, 1fr)", alignItems: "center", columnGap: 14, rowGap: 12, padding: "16px 4px 0" }}>
                <span style={label}>이름 패턴</span>
                <input value={draft.pattern} onChange={(event) => set("pattern", event.target.value)} placeholder="*.tmp, invoice*" aria-label="파일명 패턴" style={control} />

                <span style={{ ...label, alignSelf: "start", paddingTop: 9 }}>제외 폴더</span>
                <div style={{ display: "grid", gap: 6 }}>
                  <input value={excludeInput} onChange={(event) => setExcludeInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); addExclude(); } }} placeholder="\Windows\Temp 입력 후 Enter" aria-label="제외할 폴더 입력" style={mono} />
                  {customExcludes.length > 0 && <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {customExcludes.map((path) => <span key={path} style={{ display: "inline-flex", alignItems: "center", gap: 2, height: 24, padding: "0 4px 0 10px", fontSize: 11.5, fontFamily: "var(--mono)", borderRadius: 999, background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                      {path}
                      <button type="button" aria-label={`${path} 제외 해제`} onClick={() => set("excludePaths", draft.excludePaths.filter((p) => p !== path))} style={{ display: "grid", placeItems: "center", width: 18, height: 18, padding: 0, border: "none", borderRadius: "50%", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><CloseOutlinedIcon sx={{ fontSize: 13 }} /></button>
                    </span>)}
                  </div>}
                </div>

                <span style={label}>레코드</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  <Segmented label="종류" options={[{ value: "file", label: "파일" }, { value: "dir", label: "폴더" }, { value: "all", label: "둘 다" }]} value={draft.kind} onChange={(value) => set("kind", value)} />
                  <Segmented label="레코드 할당" options={[{ value: "all", label: "전체" }, { value: "1", label: "사용 중" }, { value: "0", label: "비사용", title: "in_use=0 — 삭제 후 아직 재사용되지 않은 레코드 등" }]} value={draft.inUse} onChange={(value) => set("inUse", value)} />
                </div>

                <span style={label}>크기</span>
                <select value={draft.size} onChange={(event) => set("size", event.target.value as SizePreset)} aria-label="크기" style={{ ...control, width: 180 }}>
                  {(Object.keys(SIZE_PRESETS) as SizePreset[]).map((value) => <option key={value} value={value}>{value === "all" ? "모든 크기" : SIZE_PRESETS[value].label}</option>)}
                </select>

                <span style={{ ...label, alignSelf: "start", paddingTop: 2 }}>저장 상태</span>
                <div style={{ display: "grid", gap: 10 }}>
                  <Switch on={draft.pathIncomplete} onChange={(on) => set("pathIncomplete", on)} label="경로 불완전만" hint="부모 연결이 확인되지 않은 레코드" />
                  <Switch on={draft.residentOnly} onChange={(on) => set("residentOnly", on)} label="Resident만" hint="본문이 $MFT 안에 있어 바로 열람 가능" />
                  <Switch on={draft.siBeforeFn} onChange={(on) => set("siBeforeFn", on)} label="SI 생성 < FN 생성" hint="두 저장 값의 비교 — 조작 여부 판단은 아님" />
                </div>

                {draft.timeMode !== "all" && <>
                  <span style={{ ...label, alignSelf: "start", paddingTop: 6 }}>검사할 시각</span>
                  <div role="group" aria-label="검사할 시각" style={{ display: "grid", gridTemplateColumns: "28px repeat(4, minmax(0, 1fr))", gap: 4, alignItems: "center", fontSize: 11 }}>
                    <span />
                    {TIME_GRID.map((c) => <span key={c.label} style={{ textAlign: "center", color: "var(--text-faint)" }}>{c.label}</span>)}
                    {(["si", "fn"] as const).map((side) => <Fragment key={side}>
                      <span style={{ fontWeight: 650, color: "var(--text-dim)" }}>{side.toUpperCase()}</span>
                      {TIME_GRID.map((c) => {
                        const key = c[side];
                        const on = draft.timeKeys.includes(key);
                        return <button key={key} type="button" aria-pressed={on} aria-label={MFT_TIME_FIELDS[key].short} onClick={() => setDraft((previous) => withTimeKeys(previous, on ? previous.timeKeys.filter((k) => k !== key) : [...previous.timeKeys, key]))} style={{ height: 26, borderRadius: 6, cursor: "pointer", fontSize: 12, border: `1px solid ${on ? "var(--accent)" : "var(--border-subtle)"}`, background: on ? "var(--accent-subtle)" : "transparent", color: on ? "var(--accent)" : "transparent" }}>✓</button>;
                      })}
                    </Fragment>)}
                  </div>
                </>}

                <span style={label}>정렬</span>
                <div style={{ display: "flex", gap: 8 }}>
                  <select value={draft.sortKey} onChange={(event) => set("sortKey", event.target.value)} aria-label="정렬 기준" style={{ ...control, width: 180 }}>
                    <option value="path">경로</option>
                    <option value="name">파일 이름</option>
                    {Object.entries(MFT_TIME_FIELDS).map(([value, spec]) => <option key={value} value={value}>{spec.short}</option>)}
                    <option value="size">크기</option>
                  </select>
                  <Segmented label="정렬 방향" options={[{ value: "asc", label: "오름차순" }, { value: "desc", label: "내림차순" }]} value={draft.sortDesc ? "desc" : "asc"} onChange={(value) => set("sortDesc", value === "desc")} />
                </div>
              </div>
            )}
          </div>
        </div>

        <footer style={{ display: "flex", alignItems: "center", gap: 6, padding: "12px 16px 12px 22px", borderTop: "1px solid var(--border-subtle)", background: "var(--bg-elevated)" }}>
          <span role="status" aria-live="polite" style={{ fontSize: 12.5, color: count.failed ? "var(--danger)" : "var(--text-dim)", fontVariantNumeric: "tabular-nums" }}>
            {bounds.error ? "시각을 확인하세요" : count.failed ? "건수를 세지 못했습니다" : count.loading || count.value === null ? "건수 확인 중…" : <><strong style={{ fontSize: 15, fontWeight: 650, color: "var(--text)" }}>{count.value.toLocaleString()}</strong>건</>}
          </span>
          <button type="button" onClick={() => { setDraft({ ...DEFAULT_LIST_FILTERS }); setCustomExtension(false); }} style={{ ...ghost, marginLeft: "auto" }}>초기화</button>
          <button type="button" onClick={onClose} style={ghost}>취소</button>
          <button type="button" data-dialog-autofocus disabled={Boolean(bounds.error)} onClick={() => { onApply(draft); onClose(); }} title={bounds.error ?? undefined} style={{ height: 34, padding: "0 20px", fontSize: 12.5, fontWeight: 650, border: "none", borderRadius: 8, background: "var(--accent)", color: "var(--bg-panel)", cursor: bounds.error ? "not-allowed" : "pointer", opacity: bounds.error ? 0.4 : 1 }}>적용</button>
        </footer>
      </div>
    </div>
  );
}
