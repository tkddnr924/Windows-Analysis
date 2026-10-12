import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { decodeBase64, decodeHex, decodeUrl } from "./textDecoders.ts";

const utf16le = (text: string) => Buffer.from(text, "utf16le").toString("base64");

test("PowerShell -EncodedCommand payloads decode as UTF-16LE", () => {
  assert.deepEqual(decodeBase64(utf16le("Write-Output 'hi'")), { ok: true, text: "Write-Output 'hi'", encoding: "UTF-16LE" });
});

test("Base64 of UTF-8 text decodes as UTF-8, ignoring quotes and line breaks", () => {
  const encoded = Buffer.from("Write-Output \"=== 디스크 ===\"", "utf8").toString("base64");
  assert.deepEqual(decodeBase64(`'${encoded.slice(0, 10)}\n${encoded.slice(10)}'`), { ok: true, text: "Write-Output \"=== 디스크 ===\"", encoding: "UTF-8" });
});

test("Base64URL alphabet and missing padding are accepted", () => {
  const encoded = Buffer.from("a?b>c", "utf8").toString("base64url");
  assert.deepEqual(decodeBase64(encoded), { ok: true, text: "a?b>c", encoding: "UTF-8" });
});

test("non-Base64 input and binary payloads are reported, not shown as text", () => {
  assert.equal(decodeBase64("not base64!").ok, false);
  assert.equal(decodeBase64(Buffer.from([0xff, 0xfe, 0x00, 0x81, 0x9c]).toString("base64")).ok, false);
});

test("URL decoding handles %XX, UTF-8 sequences and plus signs", () => {
  assert.deepEqual(decodeUrl("a%20b+c%2F%ED%95%9C"), { ok: true, text: "a b c/한", encoding: "URL" });
  assert.equal(decodeUrl("%E0%A4%A").ok, false);
});

test("hex decoding accepts spaced or 0x-prefixed bytes", () => {
  assert.deepEqual(decodeHex("0x48 0x69"), { ok: true, text: "Hi", encoding: "UTF-8" });
  assert.equal(decodeHex("4G").ok, false);
});
