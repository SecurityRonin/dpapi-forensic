# dpapi-forensic

[![Crates.io](https://img.shields.io/crates/v/dpapi-core.svg)](https://crates.io/crates/dpapi-core)
[![Docs.rs](https://docs.rs/dpapi-core/badge.svg)](https://docs.rs/dpapi-core)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/dpapi-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/dpapi-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-db61a2.svg)](https://github.com/sponsors/h4x0r)

**Parse and decrypt Windows DPAPI from raw bytes — `DPAPI_BLOB`, AES/3DES blob decryption given a master key, and Chrome/Edge `v10`/`v20` cookie unwrap — with audited crypto and zero I/O.**

DPAPI is one of the largest Windows credential-protection surfaces: Chrome/Edge
saved passwords and the cookie key, Credential Manager, Vault, Wi-Fi keys, and
the master-key files themselves. The blob format and the decrypt-given-key
crypto are identical on disk and in live memory — so `dpapi-core` is a pure
`&[u8]`-in library that both a memory tool and a disk tool can share.

## Quick start

```toml
[dependencies]
dpapi-core = "0.1"
```

```rust
use dpapi_core::{parse_dpapi_blob, decrypt_dpapi_blob};

// `master_key` comes from your key source (LSASS cache in memory, or a
// master-key file + password derivation on disk).
let blob = parse_dpapi_blob(raw_blob_bytes)?;
let plaintext = decrypt_dpapi_blob(&blob, master_key)?;
# Ok::<(), dpapi_core::DpapiError>(())
```

Chrome/Edge cookies (`Local State` key already recovered):

```rust
use dpapi_core::{detect_chrome_cookie_encoding, decrypt_v10_cookie, ChromeCookieEncoding};

if let ChromeCookieEncoding::V10 { nonce, ciphertext } =
    detect_chrome_cookie_encoding(encrypted_value)
{
    let cookie = decrypt_v10_cookie(&nonce, &ciphertext, &aes_key)?;
}
# Ok::<(), dpapi_core::DpapiError>(())
```

## What it does

`dpapi-core` (the library) is byte-oriented and performs no I/O:

- **`parse_dpapi_blob(&[u8])`** — decode the `DPAPI_BLOB` wire format: version,
  master-key GUID, description, algorithm IDs, HMAC key, ciphertext, and HMAC.
- **`decrypt_dpapi_blob(blob, master_key)`** — derive the session key
  (HMAC-SHA1) and decrypt with AES-256-CBC or 3DES-CBC.
- **`detect_chrome_cookie_encoding` / `decrypt_v10_cookie`** — classify a
  Chrome/Edge `encrypted_value` (`v10`/`v20`/classic-DPAPI/raw) and unwrap the
  AES-256-GCM variants.

All cryptography uses audited [RustCrypto](https://github.com/RustCrypto) crates
(`aes`, `aes-gcm`, `cbc`, `des`, `hmac`, `sha1`, `sha2`). No primitive is
hand-rolled. A bad key, IV length, or HMAC surfaces as a typed `DpapiError` —
the library never fabricates plausible-but-wrong plaintext.

## Status

Step 1 (this release) ships the byte-oriented `dpapi-core` primitives, validated
by the unit tests carried over from `memory-forensic`. The `dpapi-forensic`
crate is a stub that re-exports `dpapi-core` and documents the roadmap.

Step 2 (planned):

- **`masterkey.rs`** in `dpapi-core` — parse master-key files
  (`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`) and derive the key-protection key
  from the user password (SHA1 → PBKDF2-HMAC) or the domain backup key.
- **`dpapi-forensic`** auditor — enumerate and decrypt Chrome/Edge passwords +
  cookie key, Credential Manager, Vault, and Wi-Fi keys on an acquired
  filesystem, emitting graded `forensicnomicon` findings.
- **`dpapi4n6`** CLI per the fleet `*4n6` pattern, plus a tag-driven release
  workflow.

---

[Privacy Policy](https://securityronin.github.io/dpapi-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/dpapi-forensic/terms/) · © 2026 Security Ronin Ltd
