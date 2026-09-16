/** Encoding detection and decoding helpers for CTF automation.
 *
 *  Every decoder is validated twice: first through a charset heuristic, then
 *  by decoding and re-encoding the result and requiring an exact round-trip.
 *  That way we never claim an encoding for a string that only "mostly" fits.
 */

export const ENCODINGS = ["base64", "hex", "url", "rot13", "base58", "base92", "binary"] as const;
export type Encoding = (typeof ENCODINGS)[number];

const BASE64_CANONICAL = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BINARY_PATTERN = /^[01]+$/;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/;

/** Self-consistent Base92 alphabet: printable ASCII (0x21..0x7e) minus
 *  `"` and `\`, giving exactly 92 characters. Encoding uses radix-92
 *  big-integer arithmetic (mirroring how Base58 works), so round-trips
 *  are exact for arbitrary byte input. */
const BASE92_ALPHABET = ((): string => {
  let out = "";
  for (let i = 33; i <= 126; i++) {
    const c = String.fromCharCode(i);
    if (c === '"' || c === "\\") continue;
    out += c;
  }
  return out;
})();
const BASE92_SET: ReadonlySet<string> = new Set(BASE92_ALPHABET);
const ROT13_RE = /[A-Za-z]/g;

/** English anchor words used to gate ROT13 detection (which is otherwise
 *  self-inverse and would match nearly any alphabetic string). */
const ROT13_ANCHORS = [
  "flag",
  "this",
  "the",
  "secret",
  "hello",
  "world",
  "attack",
  "password",
  "hacker",
  "cyber",
  "ctf",
  "encrypt",
];

/* ------------------------------- generic ------------------------------- */

function radixEncodeBytes(bytes: Uint8Array, alphabet: string): string {
  const base = alphabet.length;
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let num = 0n;
  for (const byte of bytes) num = num * 256n + BigInt(byte);
  let out = "";
  while (num > 0n) {
    out = alphabet[Number(num % BigInt(base))] + out;
    num /= BigInt(base);
  }
  if (out === "") out = alphabet[0];
  return alphabet[0].repeat(zeros) + out;
}

function radixDecode(input: string, alphabet: string): Uint8Array {
  const base = alphabet.length;
  if (input.length === 0) return new Uint8Array(0);
  const idx = new Map<string, number>();
  [...alphabet].forEach((c, i) => idx.set(c, i));
  let zeros = 0;
  while (zeros < input.length && input[zeros] === alphabet[0]) zeros++;
  let num = 0n;
  for (const ch of input) {
    const v = idx.get(ch);
    if (v === undefined) throw new Error(`Invalid character for radix-${base}: "${ch}"`);
    num = num * BigInt(base) + BigInt(v);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  for (let i = 0; i < zeros; i++) bytes.unshift(0);
  return Uint8Array.from(bytes);
}

function strictUrlEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function rot13(s: string): string {
  return s.replace(ROT13_RE, (c) => {
    const code = c.charCodeAt(0);
    const base = code < 97 ? 65 : 97;
    return String.fromCharCode(((code - base + 13) % 26) + base);
  });
}

function binaryEncodeBytes(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(2).padStart(8, "0")).join(" ");
}

function isInvalidUtf8(s: string): boolean {
  return s.includes("\uFFFD");
}

/* ------------------------------- public API ----------------------------- */

export function encodeByKind(kind: string, input: string): string {
  switch (normalizeKind(kind)) {
    case "base64":
      return Buffer.from(input, "utf8").toString("base64");
    case "hex":
      return Buffer.from(input, "utf8").toString("hex");
    case "url":
      return strictUrlEncode(input);
    case "rot13":
      return rot13(input);
    case "base58":
      return radixEncodeBytes(Buffer.from(input, "utf8"), BASE58);
    case "base92":
      return radixEncodeBytes(Buffer.from(input, "utf8"), BASE92_ALPHABET);
    case "binary":
      return binaryEncodeBytes(Buffer.from(input, "utf8"));
    default:
      throw new Error(`Unknown encoding: "${kind}"`);
  }
}

export function decodeByKind(kind: string, input: string): string {
  switch (normalizeKind(kind)) {
    case "base64":
      return Buffer.from(input.replace(/\s+/g, ""), "base64").toString("utf8");
    case "hex":
      return Buffer.from(input.trim(), "hex").toString("utf8");
    case "url":
      return decodeURIComponent(input);
    case "rot13":
      return rot13(input);
    case "base58":
      return Buffer.from(radixDecode(input.replace(/\s+/g, ""), BASE58)).toString("utf8");
    case "base92":
      return Buffer.from(radixDecode(input, BASE92_ALPHABET)).toString("utf8");
    case "binary":
      return Buffer.from(binaryToBytes(input)).toString("utf8");
    default:
      throw new Error(`Unknown encoding: "${kind}"`);
  }
}

function binaryToBytes(input: string): Uint8Array {
  const bits = input.replace(/\s+/g, "");
  if (bits.length % 8 !== 0) throw new Error("Binary input length must be a multiple of 8 bits");
  const bytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

export function normalizeKind(kind: string): Encoding | undefined {
  switch (kind.toLowerCase()) {
    case "base64":
    case "b64":
      return "base64";
    case "hex":
    case "hexadecimal":
      return "hex";
    case "url":
    case "urlencode":
    case "urldecode":
      return "url";
    case "rot13":
    case "rot":
      return "rot13";
    case "base58":
    case "b58":
      return "base58";
    case "base92":
    case "b92":
      return "base92";
    case "binary":
    case "bin":
      return "binary";
    default:
      return undefined;
  }
}

/** Attempt to decode `input` with every known encoding. A candidate is only
 *  kept when the charset heuristic passes AND decoding then re-encoding
 *  reproduces the original input exactly. Returns [] when nothing fits. */
export function attemptDecode(s: string): { encoding: string; decoded: string }[] {
  const input = String(s ?? "");
  const out: { encoding: string; decoded: string }[] = [];
  for (const enc of ENCODINGS) {
    const decoded = probeDecode(enc, input);
    if (decoded !== null) out.push({ encoding: enc, decoded });
  }
  return out;
}

/** Detect which encodings an input might be. Alias of `attemptDecode`
 *  that returns just the encoding names, in canonical order. */
export function detectEncoding(s: string): string[] {
  return attemptDecode(s).map((c) => c.encoding);
}

function probeDecode(enc: Encoding, input: string): string | null {
  switch (enc) {
    case "base64": {
      const norm = input.replace(/\s+/g, "");
      if (norm.length < 4 || norm.length % 4 !== 0 || !BASE64_CANONICAL.test(norm)) return null;
      const decoded = Buffer.from(norm, "base64").toString("utf8");
      if (isInvalidUtf8(decoded) || decoded === norm) return null;
      if (Buffer.from(decoded, "utf8").toString("base64") !== norm) return null;
      return decoded;
    }
    case "hex": {
      const norm = input.trim().toLowerCase();
      if (norm.length < 6 || norm.length % 2 !== 0 || !/^[0-9a-f]+$/.test(norm)) return null;
      const decoded = Buffer.from(norm, "hex").toString("utf8");
      if (isInvalidUtf8(decoded) || decoded === norm) return null;
      if (Buffer.from(decoded, "utf8").toString("hex") !== norm) return null;
      return decoded;
    }
    case "url": {
      if (!input.includes("%")) return null;
      let decoded: string;
      try {
        decoded = decodeURIComponent(input);
      } catch {
        return null;
      }
      if (decoded === input.trim()) return null;
      if (strictUrlEncode(decoded).toLowerCase() !== input.trim().toLowerCase()) return null;
      return decoded;
    }
    case "rot13": {
      const letterCount = (input.match(ROT13_RE) || []).length;
      if (letterCount < 4) return null;
      const decoded = rot13(input);
      const lower = decoded.toLowerCase();
      if (!ROT13_ANCHORS.some((w) => lower.includes(w))) return null;
      return decoded;
    }
    case "base58": {
      const norm = input.replace(/\s+/g, "");
      if (norm.length < 4 || !BASE58_PATTERN.test(norm)) return null;
      const decoded = Buffer.from(radixDecode(norm, BASE58)).toString("utf8");
      if (isInvalidUtf8(decoded) || decoded === norm) return null;
      if (radixEncodeBytes(Buffer.from(decoded, "utf8"), BASE58) !== norm) return null;
      return decoded;
    }
    case "base92": {
      if (input.length < 2 || input.includes("\u0000")) return null;
      for (const ch of input) if (!BASE92_SET.has(ch)) return null;
      const decoded = Buffer.from(radixDecode(input, BASE92_ALPHABET)).toString("utf8");
      if (isInvalidUtf8(decoded) || decoded === input) return null;
      if (radixEncodeBytes(Buffer.from(decoded, "utf8"), BASE92_ALPHABET) !== input) return null;
      return decoded;
    }
    case "binary": {
      const norm = input.replace(/\s+/g, "");
      if (norm.length < 8 || norm.length % 8 !== 0 || !BINARY_PATTERN.test(norm)) return null;
      const bytes = binaryToBytes(input);
      const decoded = Buffer.from(bytes).toString("utf8");
      if (isInvalidUtf8(decoded) || decoded === norm) return null;
      if (binaryEncodeBytes(bytes).replace(/\s+/g, "") !== norm) return null;
      return decoded;
    }
  }
}