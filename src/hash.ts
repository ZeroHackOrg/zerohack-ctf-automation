/** Hashing utilities and a small embedded password-cracker demo. */

import { createHash } from "node:crypto";

export const HASH_ALGOS = ["md5", "sha1", "sha256", "sha512"] as const;
export type HashAlgo = (typeof HASH_ALGOS)[number];

/** ~40 commonly used (and commonly breached) passwords, embedded so
 *  `passwordCrack` works fully offline and deterministically. */
export const EMBEDDED_PASSWORDS: readonly string[] = [
  "password",
  "123456",
  "12345678",
  "123456789",
  "1234567890",
  "qwerty",
  "abc123",
  "password1",
  "password123",
  "111111",
  "1234567",
  "iloveyou",
  "letmein",
  "admin",
  "welcome",
  "monkey",
  "dragon",
  "master",
  "sunshine",
  "princess",
  "football",
  "shadow",
  "superman",
  "trustno1",
  "rasputin",
  "hunter2",
  "batman",
  "lovely",
  "dragon1",
  "admin123",
  "changeme",
  "passw0rd",
  "secret",
  "server",
  "welcome1",
  "qwerty123",
  "1q2w3e4r",
  "mypass",
  "summer",
  "login",
  "P@ssw0rd",
  "starwars",
];

export function hash(algo: string, input: string): string {
  const norm = algo.toLowerCase();
  if (!(HASH_ALGOS as readonly string[]).includes(norm)) {
    throw new Error(`Unsupported hash algorithm: "${algo}" (use ${HASH_ALGOS.join(", ")})`);
  }
  return createHash(norm).update(String(input ?? "")).digest("hex");
}

export interface CrackResult {
  algo: HashAlgo;
  hash: string;
  password: string;
}

/** Look up a password in the embedded wordlist (or a custom one) whose hash
 *  under `algo` matches `hashHex`. Returns null when nothing matches. */
export function passwordCrack(
  algo: string,
  hashHex: string,
  wordlist: Iterable<string> = EMBEDDED_PASSWORDS
): CrackResult | null {
  const norm = algo.toLowerCase() as HashAlgo;
  if (!(HASH_ALGOS as readonly string[]).includes(norm)) {
    throw new Error(`Unsupported hash algorithm: "${algo}" (use ${HASH_ALGOS.join(", ")})`);
  }
  const target = String(hashHex ?? "").toLowerCase().trim();
  for (const candidate of wordlist) {
    if (createHash(norm).update(candidate).digest("hex") === target) {
      return { algo: norm, hash: target, password: candidate };
    }
  }
  return null;
}