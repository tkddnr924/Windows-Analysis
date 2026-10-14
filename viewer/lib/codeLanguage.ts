// Highlighting language for the code viewer. Detection only picks a default;
// the analyst can always switch. Sibling imports carry `.ts` for Node tests.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { prettyXmlOrNull } from "./xmlPretty.ts";

export type CodeLanguageId =
  | "plain" | "powershell" | "json" | "javascript" | "typescript" | "php" | "python"
  | "xml" | "html" | "shell" | "sql" | "css" | "yaml" | "vbscript" | "csharp";

export const CODE_LANGUAGES: { id: CodeLanguageId; label: string }[] = [
  { id: "plain", label: "일반 텍스트" },
  { id: "powershell", label: "PowerShell" },
  { id: "json", label: "JSON" },
  { id: "javascript", label: "JavaScript" },
  { id: "typescript", label: "TypeScript" },
  { id: "php", label: "PHP" },
  { id: "python", label: "Python" },
  { id: "xml", label: "XML" },
  { id: "html", label: "HTML" },
  { id: "shell", label: "Shell" },
  { id: "sql", label: "SQL" },
  { id: "css", label: "CSS" },
  { id: "yaml", label: "YAML" },
  { id: "vbscript", label: "VBScript" },
  { id: "csharp", label: "C#" },
];

const POWERSHELL = /\b(powershell(\.exe)?|pwsh)\b|\b(Get|Set|New|Invoke|Start|Remove|Add|Out|Write|Import|ConvertTo|ConvertFrom)-[A-Z][A-Za-z]+|\bIEX\b|\$env:|-EncodedCommand\b|\[System\.[A-Za-z.]+\]/;

function isJson(text: string): boolean {
  if (!/^[[{]/.test(text)) return false;
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/** Best-guess language for a stored code value. */
export function detectCodeLanguage(raw: string): CodeLanguageId {
  const text = raw.trim();
  if (!text) return "plain";
  if (isJson(text)) return "json";
  if (/^<\?php/i.test(text)) return "php";
  if (/^<!doctype html|^<html[\s>]/i.test(text)) return "html";
  if (/^<\?xml/i.test(text) || prettyXmlOrNull(text) !== null) return "xml";
  if (/^#!.*\b(ba|z|da)?sh\b/.test(text)) return "shell";
  if (POWERSHELL.test(text)) return "powershell";
  if (/^\s*(def \w+\(|import \w+|from [\w.]+ import |class \w+.*:\s*$)/m.test(text)) return "python";
  if (/^\s*(SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE)\b/i.test(text)) return "sql";
  if (/\b(function\s*\w*\s*\(|var |let |const |=>|ActiveXObject|WScript\.)/.test(text)) return "javascript";
  return "plain";
}
