# 3. Audited RustCrypto only — never hand-roll, never fabricate plaintext

Date: 2026-07-24
Status: Accepted

## Context

DPAPI decryption is standard, solved cryptography: HMAC-SHA1/SHA512 session-key
derivation, AES-256-CBC and 3DES-CBC blob decryption, and AES-256-GCM for
Chrome/Edge `v10`/`v20` cookies. The fleet crypto law
(`CLAUDE.core.md`, "Never hand-roll a cryptographic primitive, and NEVER ship
placeholder crypto") is explicit: reach for the vetted RustCrypto crates, and the
single most dangerous failure is a *placeholder* that returns plausible-but-wrong
bytes — in a forensic/security tool that is fabricated evidence.

A DPAPI recovery tool is exactly the LZNT1/fabrication-trap zone: it produces a
value (a decrypted secret) that an independent oracle can check, so any
hand-rolled or placeholder path would be both wrong and dangerous.

## Decision

1. **All cryptography is audited RustCrypto crates**, declared once in
   `[workspace.dependencies]` and consumed by `dpapi-core`: `aes`, `aes-gcm`,
   `cbc`, `cipher`, `des`, `hmac`, `sha1`, `sha2`. No primitive is hand-rolled
   (root `Cargo.toml` comment: "audited RustCrypto crates only … never hand-roll,
   cf. the fleet RC4 finding"; `core/src/decrypt.rs` imports).
2. **Failures surface as typed `DpapiError`, never a guessed plaintext.** A bad
   key, IV length, HMAC mismatch, unsupported version/algorithm, or short data is
   a distinct `DpapiError` variant (`core/src/error.rs`); `decrypt_aes256_cbc`
   maps a padding/length failure to `DecryptionFailed`/`InvalidKeyLength`.
3. **Refuse-don't-fabricate is a hard boundary.** Any path not yet implemented
   refuses loudly rather than return placeholder bytes — the RED test that landed
   the CLI is literally `9079454` "dpapi4n6 CLI decode + refuse-don't-fabricate".

## Consequences

- The library "never fabricates plausible-but-wrong plaintext" (README) — a
  wrong key is reported, not silently decrypted to garbage that reads as a secret.
- Correctness of the audited path is checkable against impacket (ADR
  [0007](decisions/0007-impacket-oracle-validation.md)), which is only meaningful
  because the crypto is the real, standard algorithm rather than a stand-in.
- The RustCrypto dependency set is compiled in unconditionally (no feature gates)
  so the shipped tool can always decrypt every supported store (fleet
  batteries-included default).
