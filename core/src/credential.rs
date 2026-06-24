//! Windows **Credential Manager** decoder.
//!
//! On-disk credential files live at `%APPDATA%\Microsoft\Credentials\<hex>` and
//! `%LOCALAPPDATA%\Microsoft\Credentials\<hex>`. Each file is impacket's
//! `CredentialFile` wrapper — `Version(4)`, `Size(4)`, `Unknown(4)`, then a
//! `Size`-byte `Data` blob that is a **DPAPI blob**. Decrypting that blob with the
//! user master key yields a `CREDENTIAL_BLOB` carrying the target, username, and
//! the secret (the stored password/credential), all UTF-16LE.
//!
//! Layout and field semantics follow impacket 0.13.1 (`impacket/dpapi.py`,
//! `CredentialFile` / `CREDENTIAL_BLOB`). This module owns only the parsing; the
//! DPAPI decrypt reuses [`crate::decrypt::decrypt_dpapi_blob`], and all crypto is
//! the existing audited RustCrypto path — no hand-rolled primitives.

use crate::blob::decode_utf16le;
use crate::error::DpapiError;

/// A decoded Credential Manager entry (impacket `CREDENTIAL_BLOB`).
///
/// `secret` is impacket's `Unknown` field — the stored credential material
/// (typically the password) for the `target`. Strings are UTF-16LE-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The credential target (impacket `Target`), e.g. `Domain:target=...`.
    pub target: String,
    /// The account username (impacket `Username`).
    pub username: String,
    /// The stored secret / password (impacket `Unknown`).
    pub secret: String,
    /// FILETIME of last write (impacket `LastWritten`).
    pub last_written: u64,
}

/// Strip the on-disk `CredentialFile` wrapper, returning the inner DPAPI blob.
///
/// Reads `Version(4)`, `Size(4)`, `Unknown(4)`, then returns exactly `Size`
/// bytes of `Data`. A truncated file (Size larger than the remaining bytes) is
/// rejected with [`DpapiError::TooShort`] rather than over-reading.
pub fn parse_credential_file(data: &[u8]) -> Result<Vec<u8>, DpapiError> {
    // RED stub: not implemented. Returns an empty blob so the downstream decode
    // fails a value/parse check rather than fabricating output.
    let _ = data;
    Ok(Vec::new())
}

/// Decrypt + decode a Credential Manager entry from its DPAPI blob bytes.
///
/// `blob_bytes` is the inner DPAPI blob (post [`parse_credential_file`]).
/// `master_key` is the 64-byte user master key. Decrypts the blob (no entropy)
/// through [`crate::decrypt::decrypt_dpapi_blob`], then parses the cleartext as a
/// `CREDENTIAL_BLOB`.
///
/// A wrong/absent master key fails the blob's Sign-HMAC and returns a
/// [`DpapiError`] — it never returns a fabricated/empty credential.
pub fn decrypt_credential(blob_bytes: &[u8], master_key: &[u8]) -> Result<Credential, DpapiError> {
    // RED stub: not implemented. Returns an empty credential (deliberately wrong)
    // so the oracle value-match test FAILS; it does NOT fabricate plausible fields.
    let _ = (blob_bytes, master_key, decode_utf16le(&[]));
    Ok(Credential {
        target: String::new(),
        username: String::new(),
        secret: String::new(),
        last_written: 0,
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
    // reproducer tests/data/build_credential_vector.py) ---
    // Master key = the tier-1 impacket-validated key.
    const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
    // The full on-disk CredentialFile (wrapper + inner DPAPI blob).
    const CRED_FILE_HEX: &str = "01000000b60100000000000001000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc600000000020000000000106600000001000020000000aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899000000000e800000000200004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000e2d6d8670704ca1daecd786fe94c133a68fd50708f3ed0ca7013b5e0bc5f61296b5a32b935d6b5404a2162bc26cf561cb7b45f58c7cc8d18305c9dd068860bd4f6cea89ea34db4acde8ebae4606ec1261e8006b104d96eb42975e0df1042aa1161e6c70af5530507238141080d7d7ea1f16a9609963b296143504a4af284826e1436641c74c6dc00d0b1731794887426fc4e4f4d440416c1874aaf34b6a74411d9ed966d73b6a8d05c8546329e7bb4222d2518ab8e2e7d8c47624ec64ecc8a0040000000e0585a675fef9ed63f72673bd9408684dc7fc86ad4926a76c432af933aeab68447e56860b1715cff46516cf38433a856b28a5d0653313a11664b98f2361e8cca";
    // The inner DPAPI blob alone (post-wrapper).
    const CRED_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc600000000020000000000106600000001000020000000aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899000000000e800000000200004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000e2d6d8670704ca1daecd786fe94c133a68fd50708f3ed0ca7013b5e0bc5f61296b5a32b935d6b5404a2162bc26cf561cb7b45f58c7cc8d18305c9dd068860bd4f6cea89ea34db4acde8ebae4606ec1261e8006b104d96eb42975e0df1042aa1161e6c70af5530507238141080d7d7ea1f16a9609963b296143504a4af284826e1436641c74c6dc00d0b1731794887426fc4e4f4d440416c1874aaf34b6a74411d9ed966d73b6a8d05c8546329e7bb4222d2518ab8e2e7d8c47624ec64ecc8a0040000000e0585a675fef9ed63f72673bd9408684dc7fc86ad4926a76c432af933aeab68447e56860b1715cff46516cf38433a856b28a5d0653313a11664b98f2361e8cca";
    // impacket-decoded plaintext fields.
    const EXPECT_TARGET: &str = "Domain:target=TERMSRV/fileserver01";
    const EXPECT_USERNAME: &str = "CORP\\jdoe";
    const EXPECT_SECRET: &str = "S3cr3t-P@ssw0rd!";

    // RED: stripping the CredentialFile wrapper yields the inner DPAPI blob.
    #[test]
    fn credential_file_wrapper_yields_inner_blob() {
        let blob = parse_credential_file(&hex(CRED_FILE_HEX)).expect("strip ok");
        assert_eq!(blob, hex(CRED_BLOB_HEX));
    }

    // RED: decrypted fields must equal impacket's CREDENTIAL_BLOB decode.
    #[test]
    fn decrypt_credential_matches_impacket() {
        let blob = hex(CRED_BLOB_HEX);
        let mk = hex(MASTER_KEY_HEX);
        let cred = decrypt_credential(&blob, &mk).expect("decrypt ok");
        assert_eq!(cred.target, EXPECT_TARGET);
        assert_eq!(cred.username, EXPECT_USERNAME);
        assert_eq!(cred.secret, EXPECT_SECRET);
    }

    // RED: full chain from the on-disk file through to impacket's fields.
    #[test]
    fn end_to_end_credential_file_to_fields() {
        let blob = parse_credential_file(&hex(CRED_FILE_HEX)).expect("strip ok");
        let mk = hex(MASTER_KEY_HEX);
        let cred = decrypt_credential(&blob, &mk).expect("decrypt ok");
        assert_eq!(cred.target, EXPECT_TARGET);
        assert_eq!(cred.username, EXPECT_USERNAME);
        assert_eq!(cred.secret, EXPECT_SECRET);
    }

    // RED: refuse, don't fabricate — a good blob with NO usable master key (an
    // all-zero key) must fail the Sign-HMAC and error, never an empty credential.
    #[test]
    fn no_usable_master_key_refuses_rather_than_fabricates() {
        let blob = hex(CRED_BLOB_HEX);
        let bad_mk = [0u8; 64];
        let result = decrypt_credential(&blob, &bad_mk);
        assert!(
            result.is_err(),
            "must error on an unusable master key, never fabricate a credential"
        );
    }
}
