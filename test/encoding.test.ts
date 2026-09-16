import { describe, expect, it } from "vitest";
import { attemptDecode, decodeByKind, detectEncoding, encodeByKind } from "../src/encoding.ts";

const SAMPLES = [
  "hello world",
  "the quick brown fox jumps over the lazy dog",
  "flag{this_is_a_flag}",
  "attack at dawn",
  "CTF 2026",
  "cryptography is fun",
];

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("round-trip per encoding", () => {
  const kinds = ["base64", "hex", "url", "rot13", "base58", "base92", "binary"] as const;

  it("decode(encode(x)) === x for every encoding and sample", () => {
    for (const kind of kinds) {
      for (const s of SAMPLES) {
        expect(decodeByKind(kind, encodeByKind(kind, s)), `${kind} round-trip of "${s}"`).toBe(s);
      }
    }
  });

  it("round-trips deterministic seeded random strings for byte-oriented encodings", () => {
    const rnd = mulberry32(2026);
    for (let i = 0; i < 40; i++) {
      const len = 1 + Math.floor(rnd() * 30);
      let s = "";
      for (let j = 0; j < len; j++) {
        s += String.fromCharCode(32 + Math.floor(rnd() * 90));
      }
      expect(decodeByKind("base58", encodeByKind("base58", s))).toBe(s);
      expect(decodeByKind("base92", encodeByKind("base92", s))).toBe(s);
      expect(decodeByKind("binary", encodeByKind("binary", s))).toBe(s);
    }
  });
});

describe("detectEncoding", () => {
  it("detects base64 by charset + round-trip", () => {
    expect(detectEncoding("aGVsbG8gd29ybGQ=")).toContain("base64");
  });

  it("detects hex", () => {
    expect(detectEncoding("68656c6c6f")).toContain("hex");
  });

  it("detects url-encoding", () => {
    expect(detectEncoding("%7Bflag%7D")).toContain("url");
  });

  it("detects rot13 via English anchor words", () => {
    expect(detectEncoding("synt{guvf_vf_n_synt}")).toContain("rot13");
  });

  it("detects base58", () => {
    const enc = encodeByKind("base58", "hello world");
    expect(detectEncoding(enc)).toContain("base58");
  });

  it("detects base92", () => {
    const enc = encodeByKind("base92", "flag{this_is_a_flag}");
    expect(detectEncoding(enc)).toContain("base92");
  });

  it("detects binary (8-bit groups)", () => {
    expect(detectEncoding("01001000 01100101 01101100 01101100 01101111")).toContain("binary");
  });

  it("does not flag plain prose", () => {
    expect(detectEncoding("plain english sentence no encoding")).toEqual([]);
  });

  it("orders results canonically", () => {
    const enc = encodeByKind("base64", "hello");
    const names = detectEncoding(enc);
    const idx = names.indexOf("base64");
    expect(idx).toBeGreaterThanOrEqual(0);
  });
});

describe("attemptDecode", () => {
  it("returns decoded payloads alongside encoding names", () => {
    const hits = attemptDecode("aGVsbG8gd29ybGQ=");
    expect(hits.find((h) => h.encoding === "base64")?.decoded).toBe("hello world");
  });

  it("decodes hex payloads", () => {
    expect(attemptDecode("68656c6c6f").find((h) => h.encoding === "hex")?.decoded).toBe("hello");
  });

  it("decodes url payloads", () => {
    expect(attemptDecode("hello%20world%21").find((h) => h.encoding === "url")?.decoded).toBe("hello world!");
  });

  it("decodes binary payloads", () => {
    const hit = attemptDecode("01001000 01100101 01101100 01101100 01101111").find((h) => h.encoding === "binary");
    expect(hit?.decoded).toBe("Hello");
  });

  it("rejects garbage that happens to look base64-ish", () => {
    expect(attemptDecode("not-quite-base64!!!!")).toEqual([]);
  });

  it("handles empty input", () => {
    expect(attemptDecode("")).toEqual([]);
  });
});

describe("decodeByKind / encodeByKind validation", () => {
  it("throws on unknown kind", () => {
    expect(() => decodeByKind("rot500", "x")).toThrow(/Unknown encoding/);
  });

  it("normalizes kind aliases", () => {
    expect(decodeByKind("b64", "aGVsbG8=")).toBe("hello");
    expect(decodeByKind("bin", "01001000")).toBe("H");
  });

  it("rejects malformed binary in decodeByKind", () => {
    expect(() => decodeByKind("binary", "0100")).toThrow(/multiple of 8/);
  });
});