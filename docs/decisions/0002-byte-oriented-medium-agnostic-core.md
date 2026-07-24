# 2. `dpapi-core` is byte-oriented and medium-agnostic, seeded from `memory-forensic`

Date: 2026-07-24
Status: Accepted

## Context

DPAPI-protected secrets are recovered from two very different sources: a **live
memory image** (the master key sits in the LSASS cache) and an **acquired disk**
(the master key comes from a master-key file plus password derivation, or a
domain backup key). A naive design would build one DPAPI decoder inside the
memory tool and a second, separate one inside the disk tool.

But the wire format and the crypto are the same on both media. The `DPAPI_BLOB`
layout, the HMAC-SHA1/SHA512 session-key derivation, and the AES-256-CBC/3DES-CBC
decryption are byte-identical regardless of where the bytes came from — **only
the *source* of the master key differs by medium**. `memory-forensic`'s
`memf-windows` already carried exactly this blob decoder for the LSASS path
(`CHANGELOG.md`: "seeded from `memory-forensic`'s `memf-windows` `dpapi/`
module").

## Decision

1. **Every `dpapi-core` entry point takes `&[u8]` and performs no I/O**
   (`core/src/lib.rs` module doc). The same code serves live-memory (LSASS) and
   on-disk artifacts (Chrome `Login Data`/`Local State`, Credential Manager,
   Vault, Wi-Fi keys).
2. **The master key is a parameter, not something the library sources.** The
   medium-specific key-source logic (LSASS cache vs. master-key files + password
   derivation) lives in callers; `decrypt_dpapi_blob(blob, master_key)` takes the
   key as input.
3. **Seed from `memory-forensic` rather than fork.** The blob/crypto was lifted
   out of `memf-windows` into this shared, standalone `dpapi-core` so both the
   memory tool and the new disk tool link one implementation (fleet "prefer our
   own crates" + DRY).

## Consequences

- No forked DPAPI crypto: a fix to session-key derivation or HMAC verification is
  made once in `dpapi-core` and every consumer inherits it.
- The library is trivially testable — pure functions over byte slices, no
  filesystem or memory-image harness needed for the crypto core.
- The medium seam is honest: `masterkey.rs` (disk key source) lives in
  `dpapi-core` as an optional path, but the *choice* of key source per medium is
  the caller's, keeping the crypto medium-agnostic.
