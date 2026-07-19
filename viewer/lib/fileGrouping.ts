/** Secondary grouping key for a result CSV, used to fold a category's flat
 * file list (e.g. BROWSER can have 100+ files once every raw SQLite table
 * dump is counted) into a second tree level by source artifact/database.
 *
 * Curated parser output uses a single underscore ("History_Visits.csv");
 * the generic raw SQLite dump uses a double underscore between the
 * sanitized db name and table name ("History__visits.csv"). Either way,
 * the piece before that separator is the natural group name.
 */
export function groupKeyFor(relativePath: string): string {
  const base = relativePath.split(/[\\/]/).pop()?.replace(/\.csv$/i, "") ?? relativePath;
  const doubleIdx = base.indexOf("__");
  if (doubleIdx !== -1) return base.slice(0, doubleIdx);
  const singleIdx = base.indexOf("_");
  if (singleIdx !== -1) return base.slice(0, singleIdx);
  return base;
}
