// Timeline filter group: a source table plus sub-keys (exec sources, browser kinds).
export interface FilterGroupState {
  tableHidden: boolean;
  hidden: ReadonlySet<string>;
}

export interface FilterGroupNext {
  tableHidden: boolean;
  hidden: Set<string>;
}

// Clicking a child while the table is hidden shows only that child.
export function toggleGroupChild(state: FilterGroupState, all: readonly string[], key: string): FilterGroupNext {
  if (state.tableHidden) return { tableHidden: false, hidden: new Set(all.filter((candidate) => candidate !== key)) };
  const hidden = new Set(state.hidden);
  if (hidden.has(key)) hidden.delete(key);
  else hidden.add(key);
  return { tableHidden: false, hidden };
}

// Fully visible → hide the table; otherwise show the table and every child.
export function toggleGroupParent(state: FilterGroupState, all: readonly string[]): FilterGroupNext {
  if (groupCheckState(state, all).checked) return { tableHidden: true, hidden: new Set(state.hidden) };
  return { tableHidden: false, hidden: new Set() };
}

export function groupCheckState(state: FilterGroupState, all: readonly string[]): { checked: boolean; indeterminate: boolean } {
  const visible = state.tableHidden ? 0 : all.filter((key) => !state.hidden.has(key)).length;
  const checked = all.length > 0 && visible === all.length;
  return { checked, indeterminate: visible > 0 && !checked };
}
