import assert from "node:assert/strict";
import test from "node:test";
import { StringStream } from "@codemirror/language";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { powershellMode } from "./powershellMode.ts";

function tokens(lines: string[]): string[] {
  const state = powershellMode.startState!(2);
  const out: string[] = [];
  for (const line of lines) {
    const stream = new StringStream(line, 2, 2);
    while (!stream.eol()) {
      const style = powershellMode.token(stream, state);
      const text = stream.current();
      if (text.trim()) out.push(`${text}:${style ?? ""}`);
      stream.start = stream.pos;
    }
  }
  return out;
}

test("commands, parameters, variables and strings get distinct styles", () => {
  assert.deepEqual(tokens(["Get-ChildItem -Path $env:TEMP 'a b' | Select-Object -First 3 # done"]), [
    "Get-ChildItem:builtin", "-Path:attribute", "$env:TEMP:variable-2", "'a b':string", "|:operator",
    "Select-Object:builtin", "-First:attribute", "3:number", "# done:comment",
  ]);
});

test("only the first word of each pipeline stage is a command", () => {
  assert.deepEqual(tokens(["sc query bits; net stop bits"]), ["sc:builtin", "query:", "bits:", ";:operator", "net:builtin", "stop:", "bits:"]);
});

test("keywords, .NET types and backtick-escaped quotes", () => {
  assert.deepEqual(tokens(['if ($x) { [System.IO.File]::Exists("a`"b") }']), [
    "if:keyword", "(:operator", "$x:variable-2", "):operator", "{:operator", "[System.IO.File]:type", ":::operator", "Exists:", "(:operator", '"a`"b":string', "):operator", "}:operator",
  ]);
});

test("here-strings, block comments and open strings continue across lines", () => {
  assert.deepEqual(tokens(["$s = @'", "Get-Item x", "'@", "Get-Date"]), ["$s:variable-2", "=:operator", "@':string", "Get-Item x:string", "'@:string", "Get-Date:builtin"]);
  assert.deepEqual(tokens(["<# note", "Remove-Item y #>", "Get-Date"]), ["<# note:comment", "Remove-Item y #>:comment", "Get-Date:builtin"]);
  assert.deepEqual(tokens(['Write-Host "a', 'b c"; Get-Date']), ["Write-Host:builtin", '"a:string', 'b c":string', ";:operator", "Get-Date:builtin"]);
});
