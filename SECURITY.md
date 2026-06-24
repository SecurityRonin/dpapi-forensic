# Security Policy

`dpapi-forensic` parses and decrypts **untrusted DPAPI artifacts** — blobs,
master-key files, and credential stores extracted from compromised or actively
hostile systems. Hostile input is the expected case, not an edge case.
Robustness against crafted structures is a core design goal, and we take reports
of crashes, hangs, or memory-safety issues seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

Security fixes are released against the latest published `0.1.x` line.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`dpapi-forensic` repository](https://github.com/SecurityRonin/dpapi-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing DPAPI blob or byte buffer,
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`dpapi-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **Audited cryptography only** — DPAPI session-key derivation and blob/cookie
  decryption use the RustCrypto crates (`aes`, `aes-gcm`, `cbc`, `des`, `hmac`,
  `sha1`, `sha2`); no primitive is hand-rolled. The library decrypts evidence
  given a key and never fabricates plausible-but-wrong output: a bad key, IV
  length, or HMAC surfaces as a typed error.
- **Bounds-checked parsing** — every length and offset in `parse_dpapi_blob` is
  validated against the actual buffer before use; out-of-range reads fall back
  rather than panic.
- **No panics on malicious input** — malformed blobs surface as a typed
  `DpapiError`, not a crash or silently-wrong plaintext.
