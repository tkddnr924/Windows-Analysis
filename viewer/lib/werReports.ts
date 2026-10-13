// Error report helpers (docs-16). Cards join records only through stored
// WerRelations (same report identifiers); unrelated records stay single.
// No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

export interface WerFilter {
  search: string;
  types: string[];
  classes: string[];
  stages: string[];
}

export const DEFAULT_WER_FILTER: WerFilter = { search: "", types: [], classes: [], stages: [] };

export const STAGE_LABELS: Record<string, string> = {
  app_error_event: "앱 오류 이벤트",
  app_hang_event: "앱 응답 없음 이벤트",
  report_generated: "보고 생성 이벤트",
  report_written: "보고서 파일",
  collected_dump: "수집 덤프",
};

export const CLASS_LABELS: Record<string, string> = {
  crash: "크래시",
  hang: "응답 없음",
  install_diagnostic: "설치 진단",
  store_update_failure: "스토어 업데이트 실패",
  unclassified: "미분류",
};

function matches(row: Cells, filter: WerFilter): boolean {
  const pick = (values: string[], value: string | undefined) => !values.length || values.includes(value ?? "");
  if (!pick(filter.types, row.error_type) || !pick(filter.classes, row.error_class) || !pick(filter.stages, row.reporting_stage)) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.app_name, row.app_path, row.module_name, row.module_path, row.exception_code, row.report_identifier, row.report_id, row.integrator_report_id, row.account, row.account_sid].some((value) => (value ?? "").toLowerCase().includes(needle));
}

/** Time order (direction), untimed last, ties by record_id (R10). */
function compareRows(a: Cells, b: Cells, direction: "asc" | "desc"): number {
  const left = a.timestamp ?? "";
  const right = b.timestamp ?? "";
  if (!left !== !right) return left ? -1 : 1;
  const order = left.localeCompare(right);
  return (direction === "asc" ? order : -order) || (a.record_id ?? "").localeCompare(b.record_id ?? "");
}

export interface WerCard<R extends Cells> {
  /** record_id of the earliest record in the group. */
  key: string;
  events: R[];
  matched: Set<string>;
}

export function buildWerCards<R extends Cells>(rows: R[], relations: Cells[], filter: WerFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): WerCard<R>[] {
  const kept = rows.filter((row) => (row.timestamp ? inPeriod(row.timestamp) : !periodSet));
  const parent = new Map<string, string>(kept.map((row) => [row.record_id ?? "", row.record_id ?? ""]));
  const find = (id: string): string => {
    let root = id;
    while (parent.get(root) !== root) root = parent.get(root) ?? root;
    parent.set(id, root);
    return root;
  };
  for (const relation of relations) {
    const a = relation.record_id ?? "";
    const b = relation.related_record_id ?? "";
    if (parent.has(a) && parent.has(b)) parent.set(find(a), find(b));
  }
  const groups = new Map<string, R[]>();
  for (const row of kept) {
    const root = find(row.record_id ?? "");
    groups.set(root, [...(groups.get(root) ?? []), row]);
  }
  const cards: WerCard<R>[] = [];
  for (const events of groups.values()) {
    const matched = new Set(events.filter((row) => matches(row, filter)).map((row) => row.record_id ?? ""));
    if (!matched.size) continue;
    const earliest = events.reduce((best, row) => (compareRows(row, best, "asc") < 0 ? row : best));
    events.sort((a, b) => compareRows(a, b, direction));
    cards.push({ key: earliest.record_id ?? "", events, matched });
  }
  return cards.sort((a, b) => compareRows(a.events[0], b.events[0], direction) || a.key.localeCompare(b.key));
}

// NTSTATUS meanings from [MS-ERREF] 2.3.1 (crash-relevant subset only).
const EXCEPTION_MEANINGS: Record<string, string> = {
  "80000002": "데이터 정렬 오류", // STATUS_DATATYPE_MISALIGNMENT
  "80000003": "중단점", // STATUS_BREAKPOINT
  "80000004": "단일 단계", // STATUS_SINGLE_STEP
  "c0000005": "메모리 접근 위반", // STATUS_ACCESS_VIOLATION
  "c0000006": "페이지 내 I/O 오류", // STATUS_IN_PAGE_ERROR
  "c0000008": "잘못된 핸들", // STATUS_INVALID_HANDLE
  "c000001d": "잘못된 명령어", // STATUS_ILLEGAL_INSTRUCTION
  "c0000025": "계속할 수 없는 예외", // STATUS_NONCONTINUABLE_EXCEPTION
  "c0000026": "잘못된 예외 처리", // STATUS_INVALID_DISPOSITION
  "c000008c": "배열 범위 초과", // STATUS_ARRAY_BOUNDS_EXCEEDED
  "c000008d": "부동소수점 비정규 피연산자", // STATUS_FLOAT_DENORMAL_OPERAND
  "c000008e": "부동소수점 0으로 나누기", // STATUS_FLOAT_DIVIDE_BY_ZERO
  "c0000090": "부동소수점 잘못된 연산", // STATUS_FLOAT_INVALID_OPERATION
  "c0000091": "부동소수점 오버플로", // STATUS_FLOAT_OVERFLOW
  "c0000094": "정수 0으로 나누기", // STATUS_INTEGER_DIVIDE_BY_ZERO
  "c0000095": "정수 오버플로", // STATUS_INTEGER_OVERFLOW
  "c0000096": "권한 있는 명령어", // STATUS_PRIVILEGED_INSTRUCTION
  "c00000fd": "스택 오버플로", // STATUS_STACK_OVERFLOW
  "c0000135": "DLL을 찾을 수 없음", // STATUS_DLL_NOT_FOUND
  "c0000139": "진입점을 찾을 수 없음", // STATUS_ENTRYPOINT_NOT_FOUND
  "c0000142": "DLL 초기화 실패", // STATUS_DLL_INIT_FAILED
  "c0000194": "잠재적 교착 상태", // STATUS_POSSIBLE_DEADLOCK
  "c0000374": "힙 손상", // STATUS_HEAP_CORRUPTION
  "c0000409": "스택 버퍼 오버런", // STATUS_STACK_BUFFER_OVERRUN
  "c0000417": "잘못된 CRT 매개변수", // STATUS_INVALID_CRUNTIME_PARAMETER
  "c0000420": "어설션 실패", // STATUS_ASSERTION_FAILURE
  "c0000602": "빠른 실패 예외", // STATUS_FAIL_FAST_EXCEPTION
};

/** `code (meaning)` for documented NTSTATUS codes; other values unchanged. */
export function exceptionLabel(code: string | undefined): string {
  if (!code) return "";
  const meaning = EXCEPTION_MEANINGS[code.trim().toLowerCase().replace(/^0x/, "")];
  return meaning ? `${code} (${meaning})` : code;
}
