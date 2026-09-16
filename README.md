<div align="center">

```
 ____________ _____   ____  _    _          _____ _  __
|___  /  ____|  __ \ / __ \| |  | |   /\   / ____| |/ /
   / /| |__  | |__) | |  | | |__| |  /  \ | |    | ' / 
  / / |  __| |  _  /| |  | |  __  | / /\ \| |    |  <  
 / /__| |____| | \ \| |__| | |  | |/ ____ \ |____| . \ 
/_____|______|_|  \_\____/|_|  |_/_/    \_\_____|_|\_\

              Fortifying the Digital Frontier
```

# @zerohack/ctf-automation · `zh-ctf`

**CTF solving automation — encoding chains, XOR brute force, hashing, flag extraction**

[![License](https://img.shields.io/badge/license-Apache--2.0-00B0BD?style=for-the-badge)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white)](tsconfig.json)
[![Zero Budget](https://img.shields.io/badge/cost-%240-00b894?style=for-the-badge)](https://zerohack.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-00B0BD?style=for-the-badge)](CONTRIBUTING.md)

**Part of the [ZeroHack](https://zerohack.org) Geek Tools ecosystem**
Category: `crypto` · `ctf` · `crypto` · `encoding` · `forensics`

</div>

---

> **⚡ Zero Budget. Zero Cloud Dependencies. Pure Local Power.**

---

## What It Does

`zh-ctf` — CTF solving automation: encoding detection/chains, single-byte XOR
brute force, hashing, embedded password cracking, and one-shot HTTP request
with CTF flag extraction.

---

## Quick Start

```bash
# From the monorepo root
git clone https://github.com/ZeroHackOrg/zerohack-geek-tools.git
cd zerohack-geek-tools && npm install
npm run geek:ctf -- detect "aGVsbG8gd29ybGQ="
```

**Standalone:**

```bash
git clone https://github.com/ZeroHackOrg/zerohack-ctf-automation.git
cd zerohack-ctf-automation && npm install
npx tsx src/bin.ts xor 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
```

### Standalone Resolution

```bash
git clone https://github.com/ZeroHackOrg/zerohack-shared.git
cd zerohack-shared && npm install && npm link
cd ../zerohack-ctf-automation && npm link @zerohack/shared
```

---

## Commands

| Command | Description |
| --- | --- |
| `detect <input...>` | Detect candidate encodings (charset heuristic + decode/re-encode round-trip). `--json` |
| `decode <kind> <input...>` | Explicitly decode `base64\|hex\|url\|rot13\|base58\|base92\|binary`. `--json` |
| `xor <hex>` | Brute-force single-byte XOR; top 5 keys by English-frequency score. `--json` |
| `hash <algo> <input>` | Digest with `md5\|sha1\|sha256\|sha512` (node:crypto). |
| `crack <algo> <hashHex>` | Recover a password from an embedded wordlist (~40 entries). `--json` |
| `http <url>` | Fetch + print status/headers, extract flags with `parseFlags`. `--json` |

**Examples:**

```bash
zh-ctf detect "aGVsbG8gd29ybGQ="
zh-ctf decode base64 "aGVsbG8gd29ybGQ="
zh-ctf hash sha256 "abc"
zh-ctf crack md5 8743b52063cd84097a65d1633f5c74f5
zh-ctf http https://example.com/flag --flag-regex 'zhctf\{[^}]+\}'
```

---

## Design Notes

- **Deterministic**: every decoder verifies a charset heuristic **and** an
  exact encode-round-trip before it is reported, so detection never depends on
  `Math.random`. No networking code runs during tests.
- `base58` and `base92` use big-integer radix encoding (the way Bitcoin does
  base58) over fixed alphabets, which round-trips exactly for arbitrary bytes.
  The base92 alphabet is printable ASCII (0x21–0x7e) minus `"` and `\`.
- ROT13 (self-inverse) is gated on English anchor words to avoid flagging
  arbitrary alphabetic strings.
- Network code lives only in `src/http.ts`; all other modules are pure.

---

## Env

None — all tools are zero-dependency, zero-config, and run offline.

---

## Tests

```bash
npm run typecheck --workspace @zerohack/ctf-automation
npm run test    --workspace @zerohack/ctf-automation
```

---

## Architecture

```
zerohack-ctf-automation/
├── src/
│   ├── bin.ts          # CLI entrypoint (commander)
│   ├── index.ts        # Re-exports
│   ├── encoding.ts     # Encoding detection + decode chains
│   ├── xor.ts          # Single-byte XOR brute force
│   ├── hash.ts         # md5/sha1/sha256/sha512 digests
│   └── http.ts         # One-shot fetch + flag extraction (network — isolated)
├── test/
│   ├── encoding.test.ts
│   ├── hash.test.ts
│   └── xor.test.ts
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE             # Apache-2.0
├── SECURITY.md
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

**Design principles:**
- Deterministic: no randomness in detection/decoding.
- Network code isolated in `src/http.ts`; all else pure.
- Zero runtime dependencies beyond `@zerohack/shared`.

---

## Security

HTTP helper makes explicit GET requests only to URLs you provide — built for
CTF challenges with flags. Does not brute-force login forms. Use only on
targets you own or are authorized to test.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Related Packages

| Package | Binary | What It Does |
|---|---|---|
| [@zerohack/shared](../zerohack-shared) | — | Types, schemas, catalog |
| [@zerohack/ctf-lab](../zerohack-ctf-lab) | `zh-lab` | CTF lab runner |
| [@zerohack/cli](../zerohack-cli) | `zh` | Unified CLI |
| [@zerohack/pal](../zerohack-pal) | `zh-pal` | Local AI assistant |
| [@zerohack/recon-bot](../zerohack-recon-bot) | `zh-recon` | Passive recon |
| [@zerohack/honeypot](../zerohack-honeypot) | `zh-honeypot` | Honeypot |
| [@zerohack/secret-scanner](../zerohack-secret-scanner) | `zh-secret` | Secret scanner |
| [@zerohack/log-analyzer](../zerohack-log-analyzer) | `zh-log` | Log forensics |
| [@zerohack/supalite-api](../zerohack-supalite-api) | `zh-api` | PostgREST API |
| [@zerohack/ssh-hardener](../zerohack-ssh-hardener) | `zh-ssh` | SSH auditor |
| [@zerohack/osint-cli](../zerohack-osint-cli) | `zh-osint` | OSINT tools |

---

## Community

- **Issues:** [GitHub Issues](https://github.com/ZeroHackOrg/zerohack-ctf-automation/issues)
- **PRs:** [Pull Requests](https://github.com/ZeroHackOrg/zerohack-ctf-automation/pulls)
- **Security:** [SECURITY.md](SECURITY.md)
- **Platform:** [zerohack.org](https://zerohack.org)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Read our [Code of Conduct](CODE_OF_CONDUCT.md) first.

## License

[Apache-2.0](LICENSE) — Copyright 2026 ZeroHack Security