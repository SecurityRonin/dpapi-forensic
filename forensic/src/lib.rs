//! Forensic auditor for DPAPI-protected stores, built on [`dpapi_core`].
//!
//! Step 1 ships the byte-oriented decrypt primitives via the re-exported
//! [`dpapi_core`]. The on-disk enumeration + grading layer is step 2 (see the
//! [`todo` module](crate::todo)).

pub use dpapi_core;

/// Roadmap for the step-2 on-disk auditor. Not yet implemented — this module
/// exists to anchor the plan.
///
/// Reader/enumeration auditors (each enumerates a DPAPI-protected store on an
/// acquired filesystem, decrypts it through [`dpapi_core`], and emits graded
/// `forensicnomicon` `report::Finding`s):
///
/// - **Chrome/Edge**: `Login Data` saved passwords + the `Local State` cookie
///   key, then `Cookies` decryption via
///   [`dpapi_core::detect_chrome_cookie_encoding`] /
///   [`dpapi_core::decrypt_v10_cookie`].
/// - **Credential Manager**: `%APPDATA%\Microsoft\Credentials\` blobs.
/// - **Vault**: `%APPDATA%\Microsoft\Vault\` / `%LOCALAPPDATA%\Microsoft\Vault\`.
/// - **Wi-Fi keys**: `Wlansvc` profile blobs.
///
/// Key-source layer (the disk counterpart of memf's LSASS `dpapi_keys.rs`):
///
/// - **`masterkey.rs`** in `dpapi-core`: parse master-key files at
///   `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` and derive the key-protection
///   key from the user password (SHA1 -> PBKDF2-HMAC) or the domain backup key
///   (`pbkdf2` crate). Same *consumer* as the existing decrypt path, different
///   *source* of keys.
///
/// CLI:
///
/// - **`dpapi4n6`** binary per the fleet `*4n6` pattern.
pub mod todo {}
