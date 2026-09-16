/** Single-byte XOR brute force with English letter-frequency scoring. */

export interface XorCandidate {
  key: number;
  score: number;
  plaintext: string;
}

/** Relative English letter frequencies (percentage scale), indexed by
 *  lowercase letter. Space gets a fixed bonus; control bytes are harshly
 *  penalized so binary garbage never wins the ranking. */
const LETTER_WEIGHTS: Record<string, number> = {
  e: 12.7,
  t: 9.06,
  a: 8.17,
  o: 7.51,
  i: 6.97,
  n: 6.75,
  s: 6.33,
  h: 6.09,
  r: 5.99,
  d: 4.25,
  l: 4.03,
  c: 2.78,
  u: 2.76,
  m: 2.41,
  w: 2.36,
  f: 2.23,
  g: 2.02,
  y: 1.97,
  p: 1.93,
  b: 1.49,
  v: 0.98,
  k: 0.77,
  j: 0.15,
  x: 0.15,
  q: 0.1,
  z: 0.07,
};

const SPACE_WEIGHT = 4.0;
const PUNCT_WEIGHT = 0.35;
const CONTROL_PENALTY = 10;

function englishScore(text: string): number {
  let score = 0;
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (code === 32) score += SPACE_WEIGHT;
    else if (code >= 65 && code <= 90) score += LETTER_WEIGHTS[ch.toLowerCase()] ?? 0;
    else if (code >= 97 && code <= 122) score += LETTER_WEIGHTS[ch] ?? 0;
    else if (code >= 33 && code <= 126) score += PUNCT_WEIGHT;
    else score -= CONTROL_PENALTY;
  }
  return score / Math.max(1, text.length);
}

function parseHex(hex: string): Buffer {
  const clean = String(hex ?? "")
    .replace(/\s+/g, "")
    .replace(/^0x/i, "");
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error(`Invalid hex input: "${hex}"`);
  }
  return Buffer.from(clean, "hex");
}

/** Brute-force every key 0-255 against the hex-encoded ciphertext, score the
 *  resulting plaintext against English letter frequencies, and return the top
 *  5 candidates sorted by score descending (ties broken by lowest key). */
export function singleByteXor(hex: string): XorCandidate[] {
  const bytes = parseHex(hex);
  const candidates: XorCandidate[] = [];
  for (let key = 0; key <= 255; key++) {
    const xored = Buffer.from(bytes.map((b) => b ^ key));
    const plaintext = xored.toString("latin1");
    candidates.push({ key, score: englishScore(plaintext), plaintext });
  }
  candidates.sort((a, b) => b.score - a.score || a.key - b.key);
  return candidates.slice(0, 5);
}