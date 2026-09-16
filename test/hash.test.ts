import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { EMBEDDED_PASSWORDS, hash, passwordCrack } from "../src/hash.ts";

const VECTORS: { algo: string; input: string; digest: string }[] = [
  { algo: "md5", input: "abc", digest: "900150983cd24fb0d6963f7d28e17f72" },
  { algo: "sha1", input: "abc", digest: "a9993e364706816aba3e25717850c26c9cd0d89d" },
  { algo: "sha256", input: "abc", digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
  {
    algo: "sha512",
    input: "abc",
    digest:
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  },
];

describe("hash", () => {
  it("produces known digests for every supported algorithm", () => {
    for (const { algo, input, digest } of VECTORS) {
      expect(hash(algo, input)).toBe(digest);
      expect(hash(algo.toUpperCase(), input)).toBe(digest);
    }
  });

  it("round-trips against node:crypto for arbitrary input", () => {
    for (const algo of ["md5", "sha1", "sha256", "sha512"] as const) {
      expect(hash(algo, "zero h4ck 2026")).toBe(createHash(algo).update("zero h4ck 2026").digest("hex"));
    }
  });

  it("rejects unsupported algorithms", () => {
    expect(() => hash("bcrypt", "x")).toThrow(/Unsupported hash algorithm/);
  });
});

describe("passwordCrack", () => {
  it("recovers a password from the embedded wordlist", () => {
    const target = createHash("md5").update("hunter2").digest("hex");
    const found = passwordCrack("md5", target);
    expect(found).not.toBeNull();
    expect(found?.password).toBe("hunter2");
    expect(found?.algo).toBe("md5");
  });

  it("works per algorithm with case-insensitive hash comparison", () => {
    const target = createHash("sha256").update("dragon").digest("hex").toUpperCase();
    const found = passwordCrack("sha256", target);
    expect(found?.password).toBe("dragon");
  });

  it("returns null when nothing in the wordlist matches", () => {
    const target = createHash("sha256").update("not-in-the-list-xyz").digest("hex");
    expect(passwordCrack("sha256", target)).toBeNull();
  });

  it("honors a custom wordlist", () => {
    const target = createHash("sha1").update("bond007").digest("hex");
    expect(passwordCrack("sha1", target, ["james", "bond007", "moneypenny"])?.password).toBe("bond007");
    expect(passwordCrack("sha1", target, ["james", "moneypenny"])).toBeNull();
  });

  it("embeds at least 40 passwords and they all hash to valid hex", () => {
    expect(EMBEDDED_PASSWORDS.length).toBeGreaterThanOrEqual(40);
    for (const p of EMBEDDED_PASSWORDS) {
      expect(hash("sha256", p)).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("rejects unsupported algorithms", () => {
    expect(() => passwordCrack("argon2", "00".repeat(16))).toThrow(/Unsupported hash algorithm/);
  });
});