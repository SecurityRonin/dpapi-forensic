# dpapi-forensic

**Parse and decrypt Windows DPAPI from raw bytes — `DPAPI_BLOB`, AES/3DES blob decryption given a master key, and Chrome/Edge `v10`/`v20` cookie unwrap — with audited crypto and zero I/O.**

```rust
use dpapi_core::{parse_dpapi_blob, decrypt_dpapi_blob};

// `master_key` comes from your key source (LSASS cache in memory, or a
// master-key file + password derivation on disk).
let blob = parse_dpapi_blob(raw_blob_bytes)?;
let plaintext = decrypt_dpapi_blob(&blob, master_key)?;
# Ok::<(), dpapi_core::DpapiError>(())
```

**[GitHub Repository →](https://github.com/SecurityRonin/dpapi-forensic)**

---

## What it does

DPAPI is one of the largest Windows credential-protection surfaces: Chrome/Edge saved passwords and the cookie key, Credential Manager, Vault, Wi-Fi keys, and the master-key files themselves. The blob format and the decrypt-given-key crypto are identical on disk and in live memory — so `dpapi-core` is a pure `&[u8]`-in library that both a memory tool and a disk tool can share.

`dpapi-core` (the library) is byte-oriented and performs no I/O:

- **`parse_dpapi_blob(&[u8])`** — decode the `DPAPI_BLOB` wire format: version, master-key GUID, description, algorithm IDs, HMAC key, ciphertext, and HMAC.
- **`decrypt_dpapi_blob(blob, master_key)`** — derive the session key (HMAC-SHA1) and decrypt with AES-256-CBC or 3DES-CBC.
- **`detect_chrome_cookie_encoding` / `decrypt_v10_cookie`** — classify a Chrome/Edge `encrypted_value` (`v10`/`v20`/classic-DPAPI/raw) and unwrap the AES-256-GCM variants.

## Audited crypto, no fabrication

All cryptography uses audited [RustCrypto](https://github.com/RustCrypto) crates (`aes`, `aes-gcm`, `cbc`, `des`, `hmac`, `sha1`, `sha2`). No primitive is hand-rolled. A bad key, IV length, or HMAC surfaces as a typed `DpapiError` — the library never fabricates plausible-but-wrong plaintext.

## Status

Step 1 (this release) ships the byte-oriented `dpapi-core` primitives, validated by the unit tests carried over from `memory-forensic`. The `dpapi-forensic` crate is a stub that re-exports `dpapi-core` and documents the roadmap.

Step 2 (planned): master-key file parsing and key derivation in `dpapi-core`; a `dpapi-forensic` auditor that enumerates and decrypts Chrome/Edge passwords + cookie key, Credential Manager, Vault, and Wi-Fi keys on an acquired filesystem, emitting graded `forensicnomicon` findings; and a `dpapi4n6` CLI per the fleet `*4n6` pattern.

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/dpapi-forensic) · © 2026 Security Ronin Ltd.
