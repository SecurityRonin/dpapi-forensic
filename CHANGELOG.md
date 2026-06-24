# Changelog

All notable changes to `dpapi-forensic` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — `dpapi-core` (library)

- Pure-Rust, byte-oriented DPAPI library seeded from `memory-forensic`'s
  `memf-windows` `dpapi/` module — every entry point takes `&[u8]` and performs
  no I/O, so the same code serves live-memory and on-disk artifacts.
- `blob::parse_dpapi_blob(&[u8])` — parse the `DPAPI_BLOB` wire format (version,
  master-key GUID, description, algorithm IDs, HMAC key, ciphertext, HMAC).
- `decrypt::decrypt_dpapi_blob(blob, master_key)` — derive the session key
  (HMAC-SHA1) and decrypt with AES-256-CBC or 3DES-CBC; plus
  `decrypt_aes256_cbc` and `verify_hmac_sha1` primitives.
- `chrome::detect_chrome_cookie_encoding(&[u8])` and `decrypt_v10_cookie` —
  Chrome/Edge `v10`/`v20` AES-256-GCM cookie unwrap and classic-DPAPI prefix
  detection.
- `error::DpapiError` — typed errors for short data, unsupported
  version/algorithm, key/IV length, decryption failure, and HMAC mismatch.
- All cryptography uses audited RustCrypto crates; no hand-rolled primitives.

### Added — `dpapi-forensic` (auditor)

- Stub crate re-exporting `dpapi-core`, with a documented `todo` roadmap for the
  step-2 on-disk auditor (Chrome/Edge, Credential Manager, Vault, Wi-Fi keys),
  the `masterkey.rs` key-source layer, and the `dpapi4n6` CLI.

[Unreleased]: https://github.com/SecurityRonin/dpapi-forensic/commits/main
