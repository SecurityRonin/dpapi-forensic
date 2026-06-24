//! Windows **Vault** decoder (`VAULT_VPOL` policy + `VAULT_VCRD` records).
//!
//! The Vault store (`%APPDATA%\Microsoft\Vault\<GUID>\` and the `%LOCALAPPDATA%`
//! counterpart) holds web/app credentials. Decryption is two-stage, following
//! impacket 0.13.1 (`impacket/dpapi.py` + `examples/dpapi.py`, the `VAULT` action):
//!
//! 1. **Policy** — `Policy.vpol` is a `VAULT_VPOL` whose inner `Blob` is a DPAPI
//!    blob. Decrypting it with the user master key yields `VAULT_VPOL_KEYS`: two
//!    BCRYPT-wrapped AES keys ([`VaultVpolKeys`]). These keys are *not* per-record
//!    DPAPI blobs — they are the symmetric keys that decrypt the records.
//! 2. **Records** — each `<GUID>.vcrd` is a `VAULT_VCRD`: a header, an attribute
//!    map, and per-attribute encrypted payloads. Each sizeable attribute carries
//!    an optional IV and AES-CBC ciphertext; AES-CBC-decrypting it with a VPOL key
//!    yields the cleartext, which for web credentials is a `VAULT_INTERNET_EXPLORER`
//!    schema (username / resource / password).
//!
//! This module owns only the parsing + the AES-CBC record decrypt (RustCrypto
//! `aes`/`cbc`, no hand-rolled crypto); the VPOL blob decrypt reuses
//! [`crate::decrypt::decrypt_dpapi_blob`]. If the VPOL key cannot be derived
//! (wrong master key), the policy decrypt errors loudly rather than guessing.

use crate::blob::decode_utf16le;
use crate::error::DpapiError;

/// The two AES keys recovered from a decrypted `VAULT_VPOL_KEYS` blob.
///
/// `key1` is the key impacket's `VAULT` example uses to AES-CBC-decrypt record
/// attributes; `key2` is retained for completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultVpolKeys {
    pub key1: Vec<u8>,
    pub key2: Vec<u8>,
}

/// One `VAULT_VCRD` attribute's encrypted payload.
///
/// `iv` is empty when the attribute carries no IV (impacket then uses AES-CBC
/// with a zero IV); `data` is the AES-CBC ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcrdAttribute {
    pub id: u32,
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
}

/// A decoded web credential (`VAULT_INTERNET_EXPLORER` schema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCredential {
    pub username: String,
    pub resource: String,
    pub password: String,
}

/// Strip the `VAULT_VPOL` wrapper, returning the inner DPAPI blob bytes.
///
/// Reads `Version(4)`, `Guid(16)`, length-prefixed `Description`, `Unknown(12)`,
/// `Size(4)`, `Guid2(16)`, `Guid3(16)`, `KeySize(4)`, then `KeySize` bytes of the
/// inner DPAPI blob.
pub fn parse_vpol_file(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    // RED stub: not implemented. Empty blob so downstream decode fails a check.
    let _ = (data, decode_utf16le(&[]));
    Ok(Vec::new())
}

/// Decrypt the VPOL policy blob with the master key → the two AES keys.
///
/// `vpol_blob` is the inner DPAPI blob (post [`parse_vpol_file`]). A wrong/absent
/// master key fails the blob's Sign-HMAC and returns a [`DpapiError`] — it never
/// returns guessed keys.
pub fn decrypt_vpol_keys(vpol_blob: &[u8], master_key: &[u8]) -> Result<VaultVpolKeys, DpapiError> {
    // RED stub: not implemented. Empty keys so the oracle value-match test FAILS;
    // it does NOT fabricate plausible key material.
    let _ = (vpol_blob, master_key);
    Ok(VaultVpolKeys {
        key1: Vec::new(),
        key2: Vec::new(),
    })
}

/// Parse a `VAULT_VCRD` record into its encrypted attributes.
pub fn parse_vcrd_attributes(vcrd: &[u8]) -> Result<Vec<VcrdAttribute>, DpapiError> {
    // RED stub: not implemented. No attributes so the decrypt test FAILS.
    let _ = vcrd;
    Ok(Vec::new())
}

/// AES-CBC-decrypt one VCRD attribute with a VPOL key.
///
/// Mirrors impacket's `VAULT` example: AES-CBC with `attr.iv` when a 16-byte IV is
/// present, else a zero IV; the payload is decrypted without PKCS#7 unpadding (the
/// schema parse bounds the cleartext, not a pad byte).
pub fn decrypt_vcrd_attribute(
    attr: &VcrdAttribute,
    vpol_key: &[u8],
) -> Result<Vec<u8>, DpapiError> {
    // RED stub: not implemented. Returns a typed error — NEVER fabricated
    // plaintext for a forensic secret.
    let _ = (attr, vpol_key);
    Err(DpapiError::DecryptionFailed)
}

/// Parse a decrypted `VAULT_INTERNET_EXPLORER` cleartext into a [`WebCredential`].
pub fn parse_internet_explorer(cleartext: &[u8]) -> Result<WebCredential, DpapiError> {
    // RED stub: not implemented. Empty fields so the value-match test FAILS.
    let _ = cleartext;
    Ok(WebCredential {
        username: String::new(),
        resource: String::new(),
        password: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // --- impacket 0.13.1 oracle vector (provenance: tests/data/README.md,
    // reproducer tests/data/build_vault_vector.py) ---
    const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
    const VPOL_FILE_HEX: &str = "01000000000000000000000000000000000000000a000000760070006f006c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007601000001000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc6000000000200000000001066000000010000200000001122334455667788112233445566778811223344556677881122334455667788000000000e8000000002000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000065a02b0acc4ef1fb8f698d7e6c9214d19144177556a964a02b9c13445d8cb6b640779e5cf1e273f2f8ede6445631e12c28c81e907373f71b9d26ffca96bba17b5147feb3b70fb9ebe9aa4150a1ec63c1f4e7356e600ed1bb5c15b2f850b8f21b3fac4e658821cf41f8b779baa815284576fa06d4aa59509eb7541d331958e7ca4000000057da67b85c3f524f46e18fd82b0bcfedba543efe03877d8f7d81daef61e311df7f8509d7ee7cd25becdfac53fa47c20a4150417065518659c72f200da584e654";
    // The inner DPAPI blob alone (post-VPOL-wrapper) for the key-derivation test.
    const VPOL_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc6000000000200000000001066000000010000200000001122334455667788112233445566778811223344556677881122334455667788000000000e80000000020000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000065a02b0acc4ef1fb8f698d7e6c9214d19144177556a964a02b9c13445d8cb6b640779e5cf1e273f2f8ede6445631e12c28c81e907373f71b9d26ffca96bba17b5147feb3b70fb9ebe9aa4150a1ec63c1f4e7356e600ed1bb5c15b2f850b8f21b3fac4e658821cf41f8b779baa815284576fa06d4aa59509eb7541d331958e7ca4000000057da67b85c3f524f46e18fd82b0bcfedba543efe03877d8f7d81daef61e311df7f8509d7ee7cd25becdfac53fa47c20a4150417065518659c72f200da584e654";
    const VPOL_KEY1_HEX: &str = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    const VPOL_KEY2_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const VCRD_FILE_HEX: &str = "0000000000000000000000000000000000000000000000000000d801000000000000000040000000570069006e0064006f007700730020005700650062002000500061007300730077006f00720064002000430072006500640065006e007400690061006c0000000c0000006400000078000000000000006400000000000000000000000000000000000000000000000000a500000001100000000f1e2d3c4b5a69788796a5b4c3d2e1f0d3183526451c5a94e61918a73ef697b98b4aeee92c9d96997727f81033c97368e2dc5fde038d14400f40259325c614d74e6309d7ee0b222a3f172b072b06118cb34acbb407d6a7d73c4f2d02034715c3ca8eea7993ab826edc8ddcf92bb9a9a3176e4af211ae8d18fbbe9a9574d01d67a98ec41b9e743d3ddf616db94c33c77a00a7abd0cffb59455947816dc11ff61c";
    const ATTR_IV_HEX: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const EXPECT_USER: &str = "alice@example.com";
    const EXPECT_RES: &str = "https://portal.example.com";
    const EXPECT_PWD: &str = "V@ultP4ss!";

    // RED: stripping the VAULT_VPOL wrapper yields the inner DPAPI blob.
    #[test]
    fn vpol_wrapper_yields_inner_blob() {
        let blob = parse_vpol_file(&hex(VPOL_FILE_HEX)).expect("strip ok");
        assert_eq!(blob, hex(VPOL_BLOB_HEX));
    }

    // RED: decrypting the VPOL blob yields impacket's two AES keys.
    #[test]
    fn decrypt_vpol_keys_matches_impacket() {
        let mk = hex(MASTER_KEY_HEX);
        let keys = decrypt_vpol_keys(&hex(VPOL_BLOB_HEX), &mk).expect("vpol ok");
        assert_eq!(keys.key1, hex(VPOL_KEY1_HEX));
        assert_eq!(keys.key2, hex(VPOL_KEY2_HEX));
    }

    // RED: the VCRD parses to one attribute with the expected IV.
    #[test]
    fn vcrd_parses_attribute_with_iv() {
        let attrs = parse_vcrd_attributes(&hex(VCRD_FILE_HEX)).expect("parse ok");
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].iv, hex(ATTR_IV_HEX));
        assert!(!attrs[0].data.is_empty());
    }

    // RED: full chain — VPOL key1 AES-CBC-decrypts the VCRD attribute to the
    // VAULT_INTERNET_EXPLORER fields impacket recovered.
    #[test]
    fn end_to_end_vault_web_credential() {
        let mk = hex(MASTER_KEY_HEX);
        let vpol_blob = parse_vpol_file(&hex(VPOL_FILE_HEX)).expect("strip ok");
        let keys = decrypt_vpol_keys(&vpol_blob, &mk).expect("vpol ok");
        let attrs = parse_vcrd_attributes(&hex(VCRD_FILE_HEX)).expect("parse ok");
        let cleartext = decrypt_vcrd_attribute(&attrs[0], &keys.key1).expect("attr ok");
        let cred = parse_internet_explorer(&cleartext).expect("ie ok");
        assert_eq!(cred.username, EXPECT_USER);
        assert_eq!(cred.resource, EXPECT_RES);
        assert_eq!(cred.password, EXPECT_PWD);
    }

    // RED: refuse, don't fabricate — VPOL key derivation with NO usable master
    // key (all-zero) must fail the Sign-HMAC and error, never return keys.
    #[test]
    fn no_usable_master_key_refuses_rather_than_fabricates() {
        let bad_mk = [0u8; 64];
        let result = decrypt_vpol_keys(&hex(VPOL_BLOB_HEX), &bad_mk);
        assert!(
            result.is_err(),
            "must error when the VPOL key can't be derived, never fabricate keys"
        );
    }
}
