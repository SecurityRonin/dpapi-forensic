//! Pure-Rust, byte-oriented DPAPI library.
//!
//! `dpapi-core` parses the Windows `DPAPI_BLOB` wire format, decrypts a blob
//! **given its master key**, and unwraps Chrome/Edge `v10`/`v20` AES-256-GCM
//! cookie values. Every entry point takes `&[u8]` and performs no I/O, so the
//! same code serves both live-memory (LSASS) and on-disk artifacts (Chrome
//! `Login Data` / `Local State`, Credential Manager, Vault, Wi-Fi keys).
//!
//! The blob format and the decrypt-given-key crypto are identical on disk and
//! in memory; only the *source* of the master key differs by medium (LSASS
//! cache vs. master-key files + password derivation), which lives in callers.
//!
//! All cryptography uses audited RustCrypto crates — no hand-rolled primitives.

pub mod blob;
pub mod chrome;
pub mod decrypt;
pub mod error;
pub mod masterkey;

pub use blob::{parse_dpapi_blob, DpapiBlob};
pub use chrome::{
    decrypt_local_state_key, decrypt_v10_cookie, detect_chrome_cookie_encoding,
    parse_local_state_encrypted_key, ChromeCookieEncoding,
};
pub use decrypt::{decrypt_aes256_cbc, decrypt_dpapi_blob, verify_hmac_sha1};
pub use error::DpapiError;
pub use masterkey::{
    derive_master_key_from_domain_backup, derive_master_key_from_password,
    derive_master_key_from_prekey, parse_master_key, parse_masterkey_file, prekey_from_password,
    prekey_from_sha1, MasterKey, MasterKeyFile, MASTER_KEY_LEN,
};
