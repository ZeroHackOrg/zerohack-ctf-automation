#!/usr/bin/env node
/** zh-ctf — CTF solving automation: encoding chains, hashing, XOR brute
 *  force, one-shot HTTP requests and flag extraction. */

import { Command } from "commander";
import { table, truncate } from "@zerohack/shared";
import { attemptDecode, decodeByKind, encodeByKind } from "./encoding.ts";
import { singleByteXor } from "./xor.ts";
import { hash, passwordCrack } from "./hash.ts";
import { httpRequest } from "./http.ts";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const program = new Command();
program
  .name("zh-ctf")
  .description("CTF solving automation: encoding detection, XOR brute force, hashing, password cracking and HTTP flag grabbing.")
  .version("0.1.0", "-v, --version")
  .showHelpAfterError();

program
  .command("detect <input...>")
  .description("Detect which encodings an input might be using.")
  .option("-j, --json", "emit raw JSON")
  .action((input: string[], opts: { json?: boolean }) => {
    const s = input.join(" ");
    const found = attemptDecode(s);
    if (opts.json) return console.log(JSON.stringify({ input: s, candidates: found }, null, 2));
    if (found.length === 0) {
      console.log("No encodings detected — looks like plain text or an unknown scheme.");
      return;
    }
    console.log(table({ headers: ["ENCODING", "DECODED"], rows: found.map((c) => [c.encoding, truncate(c.decoded, 64)]) }));
  });

program
  .command("decode <kind> <input...>")
  .description("Decode input with an explicit encoding: base64|hex|url|rot13|base58|base92|binary.")
  .option("-j, --json", "emit raw JSON")
  .action((kind: string, input: string[], opts: { json?: boolean }) => {
    const s = input.join(" ");
    try {
      const decoded = decodeByKind(kind, s);
      if (opts.json) return console.log(JSON.stringify({ kind, input: s, encoded: encodeByKind(kind, decoded), decoded }, null, 2));
      console.log(`${kind} -> ${decoded}`);
    } catch (err) {
      console.error(`zh-ctf: ${errorMessage(err)}`);
      process.exit(1);
    }
  });

program
  .command("xor <hex>")
  .description("Brute-force single-byte XOR over a hex ciphertext; top 5 keys by English score.")
  .option("-j, --json", "emit raw JSON")
  .action((hex: string, opts: { json?: boolean }) => {
    try {
      const hits = singleByteXor(hex);
      if (opts.json) return console.log(JSON.stringify({ ciphertext: hex, candidates: hits }, null, 2));
      console.log(table({ headers: ["KEY", "SCORE", "PLAINTEXT"], rows: hits.map((h) => [h.key, h.score.toFixed(2), truncate(h.plaintext, 70)]) }));
    } catch (err) {
      console.error(`zh-ctf: ${errorMessage(err)}`);
      process.exit(1);
    }
  });

program
  .command("hash <algo> <input>")
  .description("Hash input with md5|sha1|sha256|sha512.")
  .action((algo: string, input: string) => {
    try {
      console.log(`${algo}(${truncate(input, 40)}) = ${hash(algo, input)}`);
    } catch (err) {
      console.error(`zh-ctf: ${errorMessage(err)}`);
      process.exit(1);
    }
  });

program
  .command("crack <algo> <hashHex>")
  .description("Try to recover a password from its hash using an embedded wordlist (~40 common passwords).")
  .option("-j, --json", "emit raw JSON")
  .action((algo: string, hashHex: string, opts: { json?: boolean }) => {
    try {
      const found = passwordCrack(algo, hashHex);
      if (!found) {
        console.error("No embedded password matched this hash.");
        process.exit(1);
      }
      if (opts.json) return console.log(JSON.stringify(found, null, 2));
      console.log(`Cracked! password = ${found.password}  (${found.algo}: ${found.hash.slice(0, 16)}…)`);
    } catch (err) {
      console.error(`zh-ctf: ${errorMessage(err)}`);
      process.exit(1);
    }
  });

program
  .command("http <url>")
  .description("Fetch a URL, print status/headers and extract any CTF flags from the body.")
  .option("-m, --method <method>", "HTTP method", "GET")
  .option("-r, --flag-regex <regex>", "extra regex to search the body for flags")
  .option("--timeout <ms>", "request timeout in ms", "10000")
  .option("-j, --json", "emit raw JSON")
  .action(async (url: string, opts: { method?: string; flagRegex?: string; timeout?: string; json?: boolean }) => {
    try {
      const res = await httpRequest(url, opts.method ?? "GET", {
        flagRegex: opts.flagRegex,
        timeoutMs: Number(opts.timeout ?? 10000),
      });
      if (opts.json) return console.log(JSON.stringify(res, null, 2));
      console.log(`HTTP ${res.status}  ${url}`);
      console.log(table({
        headers: ["HEADER", "VALUE"],
        rows: Object.entries(res.headers).map(([k, v]) => [k, truncate(v, 48)]).slice(0, 24),
      }));
      console.log(res.body.length > 0 ? truncate(res.body.replace(/\s+/g, " ").trim(), 200) : "(empty body)");
      if (res.flags.length > 0) {
        console.log(table({ headers: ["FLAG"], rows: res.flags.map((f) => [f]) }));
      } else {
        console.log("No flags found in the response body.");
      }
    } catch (err) {
      console.error(`zh-ctf: ${errorMessage(err)}`);
      process.exit(1);
    }
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(`zh-ctf: ${errorMessage(err)}`);
  process.exit(1);
});