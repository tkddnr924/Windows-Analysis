const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Title for a linked row whose table has no view spec: the first non-empty
// column that is not internal (__*), an identifier (id/*_id) or a UUID.
export function fallbackLinkedRowTitle(record: Record<string, string>): string {
  for (const [key, value] of Object.entries(record)) {
    if (!value || key.startsWith("__") || key === "id" || key.endsWith("_id")) continue;
    if (UUID_PATTERN.test(value)) continue;
    return value;
  }
  return "";
}
