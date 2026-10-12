// Display-only decoders for analyst-selected text (CodeModal). Nothing here is
// stored; failures are reported instead of showing garbled text.

export type DecodeResult = { ok: true; text: string; encoding: string } | { ok: false; error: string };

const utf8 = new TextDecoder("utf-8", { fatal: true });
const utf16 = new TextDecoder("utf-16le", { fatal: true });

// Text with control bytes other than tab/CR/LF is treated as binary.
function printable(text: string): boolean {
  return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffd]/.test(text);
}

/** Bytes as display text (UTF-16LE when it looks like it, else UTF-8); binary is reported. */
export function decodeBytes(bytes: Uint8Array): DecodeResult {
  // UTF-16LE (PowerShell -EncodedCommand): ASCII-range text has zero high bytes.
  if (bytes.length >= 2 && bytes.length % 2 === 0) {
    let zeros = 0;
    for (let index = 1; index < bytes.length; index += 2) if (bytes[index] === 0) zeros += 1;
    if (zeros * 2 >= bytes.length / 2) {
      try {
        const text = utf16.decode(bytes);
        if (printable(text)) return { ok: true, text, encoding: "UTF-16LE" };
      } catch { /* fall through */ }
    }
  }
  try {
    const text = utf8.decode(bytes);
    if (printable(text)) return { ok: true, text, encoding: "UTF-8" };
  } catch { /* fall through */ }
  return { ok: false, error: "텍스트가 아닌 바이너리 값입니다." };
}

/** Classic 16-byte hex dump: offset, hex bytes, printable ASCII. */
export function hexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.subarray(offset, offset + 16);
    const hex = Array.from(chunk, (byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = Array.from(chunk, (byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".")).join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  return lines.join("\n");
}

export function decodeBase64(input: string): DecodeResult {
  const compact = input.replace(/\s+/g, "").replace(/^['"]|['"]$/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!compact || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact) || compact.length % 4 === 1) return { ok: false, error: "Base64 형식이 아닙니다." };
  const padded = compact.replace(/=+$/, "").padEnd(Math.ceil(compact.replace(/=+$/, "").length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return { ok: false, error: "Base64 형식이 아닙니다." };
  }
  return decodeBytes(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

export function decodeUrl(input: string): DecodeResult {
  try {
    return { ok: true, text: decodeURIComponent(input.replace(/\+/g, " ")), encoding: "URL" };
  } catch {
    return { ok: false, error: "URL 인코딩 형식이 아닙니다." };
  }
}

export function decodeHex(input: string): DecodeResult {
  const compact = input.replace(/0x/gi, "").replace(/[\s,:\\x-]+/gi, "");
  if (!compact || compact.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(compact)) return { ok: false, error: "Hex 형식이 아닙니다." };
  const bytes = new Uint8Array(compact.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(compact.slice(index * 2, index * 2 + 2), 16);
  return decodeBytes(bytes);
}
