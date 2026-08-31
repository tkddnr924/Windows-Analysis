"use client";

// 모든 뷰 헤더가 공유하는 필터 컨트롤 — 버튼을 누르면 팝오버가 열려 설정하는
// 방식으로 통일한다. 트리거/팝오버 스타일은 AccountFilterChips와 동일한 규칙:
// nm-btn 트리거, 필터 적용 중이면 액센트 틴트, fixed 오버레이로 닫기.
import { useState } from "react";
import CheckIcon from "@mui/icons-material/Check";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import CalendarMonthOutlinedIcon from "@mui/icons-material/CalendarMonthOutlined";

export interface FilterOption<T extends string> {
  value: T;
  label: string;
  /** 옵션 라벨 옆 건수 표기 (선택). */
  count?: number;
  /** 옵션 고유 색 (방향·상태 등). 지정 시 라벨 색으로 쓴다. */
  color?: string;
}

/** 트리거 버튼 + 팝오버 골격. children은 팝오버 내용. */
export function FilterDropdown({
  icon,
  label,
  valueLabel,
  active = false,
  align = "left",
  minWidth = 210,
  ariaLabel,
  children,
  open,
  onToggle,
}: {
  icon?: React.ReactNode;
  label: string;
  /** 트리거에 표시할 현재 값 요약. */
  valueLabel?: string;
  /** 기본값이 아닐 때 액센트 틴트. */
  active?: boolean;
  align?: "left" | "right";
  minWidth?: number;
  ariaLabel?: string;
  children: React.ReactNode;
  open: boolean;
  onToggle: (open: boolean) => void;
}) {
  return (
    <div style={{ position: "relative", display: "inline-flex" }}>
      <button
        type="button"
        className="nm-btn"
        aria-expanded={open}
        aria-label={ariaLabel ?? label}
        onClick={() => onToggle(!open)}
        style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 5, minHeight: 31, padding: "4px 11px", background: active ? "var(--accent-subtle)" : "var(--bg-elevated)", color: active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${active ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12, fontWeight: active ? 650 : 500, whiteSpace: "nowrap" }}
      >
        {icon}
        {label}
        {valueLabel && <span style={{ color: active ? "var(--accent)" : "var(--text-faint)", fontWeight: 600 }}>{valueLabel}</span>}
      </button>
      {open && (
        <>
          <div onClick={() => onToggle(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
          <div role="group" aria-label={ariaLabel ?? label} style={{ position: "absolute", top: "calc(100% + 6px)", [align]: 0, zIndex: 41, minWidth, maxHeight: 340, overflowY: "auto", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", padding: 6 }}>
            {children}
          </div>
        </>
      )}
    </div>
  );
}

/** 다중 선택 팝오버 — ✓ 표시된 옵션을 여러 개 켤 수 있다. 빈 선택은 "전체"로
 * 취급하며, 옵션을 눌러도 팝오버는 닫히지 않는다. */
export function MultiSelectDropdown({
  icon,
  label,
  options,
  selected,
  onChange,
  align = "left",
  ariaLabel,
  allLabel = "전체",
}: {
  icon?: React.ReactNode;
  label: string;
  options: FilterOption<string>[];
  /** 켜진 값들. 빈 배열이면 전체(필터 없음). */
  selected: string[];
  onChange: (next: string[]) => void;
  align?: "left" | "right";
  ariaLabel?: string;
  allLabel?: string;
}) {
  const [open, setOpen] = useState(false);
  const active = selected.length > 0;
  const toggle = (value: string) => {
    onChange(selected.includes(value) ? selected.filter((entry) => entry !== value) : [...selected, value]);
  };
  const rowStyle = (on: boolean): React.CSSProperties => ({ width: "100%", display: "flex", alignItems: "center", gap: 7, minHeight: 32, padding: "4px 9px", background: on ? "var(--accent-subtle)" : "transparent", border: "none", borderRadius: "var(--radius-sm)", color: on ? "var(--accent)" : "var(--text)", cursor: "pointer", fontSize: 12.5, fontWeight: on ? 700 : 550, textAlign: "left" });
  return (
    <FilterDropdown icon={icon} label={label} valueLabel={active ? `· ${selected.length}개` : `· ${allLabel}`} active={active} align={align} ariaLabel={ariaLabel ?? label} open={open} onToggle={setOpen}>
      {options.length === 0 && <div style={{ padding: "8px 10px", color: "var(--text-faint)", fontSize: 12 }}>선택할 항목이 없습니다.</div>}
      {options.length > 0 && <>
        <button type="button" role="option" aria-selected={!active} onClick={() => onChange([])} style={rowStyle(!active)}
          onMouseEnter={(event) => { if (active) event.currentTarget.style.background = "var(--bg-hover)"; }}
          onMouseLeave={(event) => { event.currentTarget.style.background = !active ? "var(--accent-subtle)" : "transparent"; }}>
          <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{allLabel}</span>
          {!active && <CheckIcon sx={{ fontSize: 15, flexShrink: 0 }} />}
        </button>
        <div style={{ height: 1, background: "var(--border-subtle)", margin: "4px 2px" }} />
        {options.map((option) => {
          const on = selected.includes(option.value);
          return (
            <button key={option.value} type="button" role="option" aria-selected={on} onClick={() => toggle(option.value)} style={rowStyle(on)}
              onMouseEnter={(event) => { if (!on) event.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(event) => { event.currentTarget.style.background = on ? "var(--accent-subtle)" : "transparent"; }}>
              <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: option.color ?? "inherit" }}>{option.label}</span>
              {option.count !== undefined && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>{option.count.toLocaleString()}</span>}
              {on && <CheckIcon sx={{ fontSize: 15, flexShrink: 0 }} />}
            </button>
          );
        })}
      </>}
    </FilterDropdown>
  );
}

/** 단일 선택 팝오버 — ✓ 표시된 옵션 목록. */
export function SelectDropdown<T extends string>({
  icon,
  label,
  options,
  value,
  defaultValue,
  onChange,
  align = "left",
  ariaLabel,
}: {
  icon?: React.ReactNode;
  label: string;
  options: FilterOption<T>[];
  value: T;
  /** 이 값이 아닐 때 트리거에 액센트 틴트. 생략하면 첫 옵션. */
  defaultValue?: T;
  onChange: (value: T) => void;
  align?: "left" | "right";
  ariaLabel?: string;
}) {
  const [open, setOpen] = useState(false);
  const current = options.find((option) => option.value === value);
  const baseline = defaultValue ?? options[0]?.value;
  return (
    <FilterDropdown icon={icon} label={label} valueLabel={current ? `· ${current.label}` : undefined} active={value !== baseline} align={align} ariaLabel={ariaLabel ?? label} open={open} onToggle={setOpen}>
      {options.map((option) => {
        const selected = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="option"
            aria-selected={selected}
            onClick={() => { setOpen(false); onChange(option.value); }}
            style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, minHeight: 32, padding: "4px 9px", background: selected ? "var(--accent-subtle)" : "transparent", border: "none", borderRadius: "var(--radius-sm)", color: option.color ?? (selected ? "var(--accent)" : "var(--text)"), cursor: "pointer", fontSize: 12.5, fontWeight: selected ? 700 : 550, textAlign: "left" }}
            onMouseEnter={(event) => { if (!selected) event.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(event) => { event.currentTarget.style.background = selected ? "var(--accent-subtle)" : "transparent"; }}
          >
            <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{option.label}</span>
            {option.count !== undefined && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>{option.count.toLocaleString()}</span>}
            {selected && <CheckIcon sx={{ fontSize: 15, flexShrink: 0 }} />}
          </button>
        );
      })}
    </FilterDropdown>
  );
}

/** 정렬 팝오버 — 오래된 순/최근 순 공통 프리셋. */
export function SortDropdown({
  value,
  onChange,
  extraOptions = [],
  align = "left",
}: {
  value: string;
  onChange: (value: string) => void;
  /** "오래된 순"/"최근 순" 외 뷰 전용 정렬 옵션. */
  extraOptions?: FilterOption<string>[];
  align?: "left" | "right";
}) {
  const options: FilterOption<string>[] = [
    { value: "asc", label: "오래된 순" },
    { value: "desc", label: "최근 순" },
    ...extraOptions,
  ];
  return <SelectDropdown icon={<SortOutlinedIcon sx={{ fontSize: 15 }} />} label="정렬" options={options} value={value} defaultValue="asc" onChange={onChange} align={align} />;
}

/** 날짜(기간) 팝오버 — 전역 기간 필터를 따르지 않는 뷰 전용. */
export function DateRangeDropdown({
  start,
  end,
  onChange,
  onReset,
  align = "left",
}: {
  start: string;
  end: string;
  onChange: (next: { start: string; end: string }) => void;
  onReset: () => void;
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const active = Boolean(start || end);
  const inputStyle: React.CSSProperties = { width: "100%", minHeight: 30, padding: "0 9px", fontSize: 11.5, fontFamily: "var(--mono)", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)" };
  return (
    <FilterDropdown icon={<CalendarMonthOutlinedIcon sx={{ fontSize: 15 }} />} label="날짜" valueLabel={active ? "· 적용 중" : undefined} active={active} align={align} minWidth={252} ariaLabel="날짜 필터" open={open} onToggle={setOpen}>
      <div style={{ display: "grid", gap: 7, padding: "4px 4px 2px" }}>
        <label style={{ display: "grid", gap: 4, fontSize: 11, color: "var(--text-faint)", fontWeight: 650 }}>
          시작
          <input value={start} onChange={(event) => onChange({ start: event.target.value, end })} placeholder="YYYY-MM-DD HH:mm:ss" aria-label="시작 시각" style={inputStyle} />
        </label>
        <label style={{ display: "grid", gap: 4, fontSize: 11, color: "var(--text-faint)", fontWeight: 650 }}>
          종료
          <input value={end} onChange={(event) => onChange({ start, end: event.target.value })} placeholder="YYYY-MM-DD HH:mm:ss" aria-label="종료 시각" style={inputStyle} />
        </label>
        {active && (
          <button type="button" className="nm-btn" onClick={onReset} style={{ minHeight: 29, padding: "3px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--accent)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}>
            초기화
          </button>
        )}
      </div>
    </FilterDropdown>
  );
}

/** 헤더 검색창 — 모든 뷰 공통 스타일. */
export function HeaderSearchInput({
  value,
  onChange,
  placeholder,
  ariaLabel,
  width = 300,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  ariaLabel?: string;
  width?: number;
}) {
  return (
    <input
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      aria-label={ariaLabel ?? placeholder}
      style={{ flex: `0 1 ${width}px`, minWidth: 170, minHeight: 31, padding: "5px 10px", fontSize: 12.5, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }}
    />
  );
}

/** 모든 뷰 공통 헤더 — [아이콘][타이틀][부가정보] + (오른쪽 요소) + 컨트롤 줄.
 * 아이콘 크기·색, 타이틀 크기, 패딩이 여기 고정되어 뷰마다 달라질 수 없다. */
export function ViewHeader({
  icon: Icon,
  title,
  meta,
  right,
  titleId,
  children,
}: {
  icon: React.ElementType;
  title: React.ReactNode;
  /** 타이틀 옆 흐린 부가정보(건수 등). */
  meta?: React.ReactNode;
  /** 타이틀 줄 오른쪽 요소(상태 문구·보기 전환 등). */
  right?: React.ReactNode;
  titleId?: string;
  /** 컨트롤 줄 — [검색][계정][정렬][날짜][전용 필터] 순서로 넣는다. */
  children?: React.ReactNode;
}) {
  return (
    <header style={{ flexShrink: 0, padding: "12px 16px 10px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", minHeight: 24 }}>
        <Icon sx={{ fontSize: 18, color: "var(--accent)" }} aria-hidden="true" />
        <strong id={titleId} style={{ fontSize: 15, color: "var(--text)", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</strong>
        {meta && <span style={{ fontSize: 12, color: "var(--text-faint)", fontFamily: "var(--mono)", minWidth: 0 }}>{meta}</span>}
        {right && <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 8, minWidth: 0 }}>{right}</span>}
      </div>
      {children && <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginTop: 9 }}>{children}</div>}
    </header>
  );
}
