import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { prettyXmlOrNull } from "./xmlPretty.ts";

test("task XML fragments are indented one element per line", () => {
  const raw = "<Exec> <Command>\"C:\\a b\\x.exe\"</Command> <Arguments>-background</Arguments> </Exec>";
  assert.equal(prettyXmlOrNull(raw), "<Exec>\n  <Command>\"C:\\a b\\x.exe\"</Command>\n  <Arguments>-background</Arguments>\n</Exec>");
});

test("declarations, comments, self-closing tags and attributes keep their text", () => {
  const raw = "<?xml version=\"1.0\"?><Task a=\"1 > 0\"><!-- c --><Enabled/><Delay>PT0M30S</Delay></Task>";
  assert.equal(
    prettyXmlOrNull(raw),
    "<?xml version=\"1.0\"?>\n<Task a=\"1 > 0\">\n  <!-- c -->\n  <Enabled/>\n  <Delay>PT0M30S</Delay>\n</Task>",
  );
});

test("text that is not XML is left alone", () => {
  assert.equal(prettyXmlOrNull("C:\\Windows\\x.exe -a <b>"), null);
  assert.equal(prettyXmlOrNull("<a><b></a>"), null);
  assert.equal(prettyXmlOrNull(""), null);
});

test("text node whitespace is kept exactly", () => {
  assert.equal(prettyXmlOrNull("<Exec> <Arguments>  -flag  </Arguments> </Exec>"), "<Exec>\n  <Arguments>  -flag  </Arguments>\n</Exec>");
});

test("mixed content and xml:space=preserve fall back to the raw text", () => {
  assert.equal(prettyXmlOrNull("<a>text <b>x</b> tail</a>"), null);
  assert.equal(prettyXmlOrNull("<a xml:space=\"preserve\"> <b>x</b> </a>"), null);
});
