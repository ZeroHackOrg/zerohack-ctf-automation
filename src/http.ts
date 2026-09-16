/** One-shot HTTP helper that fetches a URL and extracts CTF flags from the
 *  response body. Network code is intentionally isolated here so every other
 *  module stays pure and unit-testable without touching the wire. */

import { parseFlags } from "@zerohack/shared";

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  flags: string[];
}

export interface HttpOptions {
  method?: string;
  flagRegex?: string;
  timeoutMs?: number;
}

export async function httpRequest(url: string, method = "GET", opts: HttpOptions = {}): Promise<HttpResult> {
  const signal = opts.timeoutMs ? AbortSignal.timeout(opts.timeoutMs) : undefined;
  const res = await fetch(url, { method: opts.method ?? method, redirect: "follow", signal });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headers[key] = value;
  });
  const body = await res.text();
  const flags = parseFlags(body);
  if (opts.flagRegex) {
    const re = new RegExp(opts.flagRegex, "gi");
    for (const m of body.matchAll(re)) flags.push(m[0]);
  }
  return { status: res.status, headers, body, flags: Array.from(new Set(flags)) };
}