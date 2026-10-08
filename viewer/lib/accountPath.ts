export function expandAccountPath(path: string, systemRoot: string): string {
  if (!systemRoot) return path;
  return path.replace(/^%systemroot%(?=\\|$)/i, () => systemRoot.replace(/\\+$/, ""));
}
