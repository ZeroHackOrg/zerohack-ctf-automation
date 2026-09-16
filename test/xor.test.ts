import { describe, expect, it } from "vitest";
import { singleByteXor } from "../src/xor.ts";

describe("singleByteXor", () => {
  const plaintext =
    "Eternal vigilance is the price of liberty, and cryptography is the pinnacle of vigilance.";

  function xorHex(text: string, key: number): string {
    return Buffer.from(Array.from(text, (c) => c.charCodeAt(0) ^ key)).toString("hex");
  }

  it("recovers the known key from a xored English string", () => {
    const key = 0x2a;
    const candidates = singleByteXor(xorHex(plaintext, key));

    expect(candidates).toHaveLength(5);
    expect(candidates.find((c) => c.key === key)?.plaintext).toBe(plaintext);
  });

  it("ranks candidates by score descending", () => {
    const candidates = singleByteXor(xorHex(plaintext, 0x42));
    for (let i = 1; i < candidates.length; i++) {
      expect(candidates[i].score).toBeLessThanOrEqual(candidates[i - 1].score);
    }
    expect(candidates[0].key).toBe(0x42);
  });

  it("breaks score ties by lowest key", () => {
    const candidates = singleByteXor("41414141");
    const scores = candidates.map((c) => c.score);
    for (let i = 1; i < scores.length; i++) {
      expect(scores[i]).toBeLessThanOrEqual(scores[i - 1]);
    }
    expect(candidates).toHaveLength(5);
    const idxA = candidates.findIndex((c) => c.key === 4);
    const idxB = candidates.findIndex((c) => c.key === 36);
    expect(idxA).toBeGreaterThanOrEqual(0);
    expect(idxB).toBeGreaterThanOrEqual(0);
    expect(candidates[idxA].score).toBe(candidates[idxB].score);
    expect(idxA).toBeLessThan(idxB);
  });

  it("tolerates whitespace and 0x prefix in hex input", () => {
    const hex = xorHex(plaintext, 7);
    const clean = singleByteXor(hex);
    const messy = singleByteXor(`0x${hex.match(/.{2}/g)?.join(" ")}`);
    expect(messy.map((c) => c.key)).toEqual(clean.map((c) => c.key));
  });

  it("throws on malformed hex", () => {
    expect(() => singleByteXor("abc")).toThrow(/Invalid hex/);
    expect(() => singleByteXor("")).toThrow(/Invalid hex/);
    expect(() => singleByteXor("zzzz")).toThrow(/Invalid hex/);
  });
});