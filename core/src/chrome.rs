use forensicnomicon::dpapi::{CHROME_COOKIE_V10, CHROME_COOKIE_V20};

use crate::error::DpapiError;

/// How a Chrome/Chromium cookie value is encoded in heap memory.
#[derive(Debug, PartialEq)]
pub enum ChromeCookieEncoding {
    /// Plaintext — no encryption prefix detected.
    Raw,
    /// Classic DPAPI blob (prefix `DPAPI`, 5 bytes). Windows 7 / no App-Bound.
    DpapiBlob(Vec<u8>),
    /// AES-256-GCM v10: `v10` + 12-byte nonce + ciphertext + 16-byte tag.
    V10 {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
    /// AES-256-GCM v20 (Chrome 127+): same wire format as v10.
    V20 {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
}

/// Detect the encoding of a raw `encrypted_value` blob from Chrome's Cookies DB.
pub fn detect_chrome_cookie_encoding(data: &[u8]) -> ChromeCookieEncoding {
    // v10/v20 require at least 3 (prefix) + 12 (nonce) = 15 bytes
    if data.len() > 15 {
        if data.starts_with(CHROME_COOKIE_V20) {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&data[3..15]);
            return ChromeCookieEncoding::V20 {
                nonce,
                ciphertext: data[15..].to_vec(),
            };
        }
        if data.starts_with(CHROME_COOKIE_V10) {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&data[3..15]);
            return ChromeCookieEncoding::V10 {
                nonce,
                ciphertext: data[15..].to_vec(),
            };
        }
    }
    if data.starts_with(b"DPAPI") {
        return ChromeCookieEncoding::DpapiBlob(data[5..].to_vec());
    }
    ChromeCookieEncoding::Raw
}

/// Decrypt a v10/v20 AES-256-GCM cookie value.
/// `key` is the 32-byte AES key from Chrome's `Local State` (already decrypted).
pub fn decrypt_v10_cookie(
    nonce: &[u8; 12],
    ciphertext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, DpapiError> {
    #[allow(deprecated)]
    // from_slice deprecated in generic-array 1.x; aes-gcm 0.10 still uses 0.14
    use aes_gcm::{
        aead::{Aead, Nonce},
        Aes256Gcm, KeyInit,
    };
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| DpapiError::InvalidKeyLength)?;
    #[allow(deprecated)]
    let nonce_ga = Nonce::<Aes256Gcm>::from_slice(nonce);
    cipher
        .decrypt(nonce_ga, ciphertext)
        .map_err(|_| DpapiError::DecryptionFailed)
}

/// Decode a Chrome/Edge `Local State` `os_crypt.encrypted_key` value into the
/// inner DPAPI blob bytes.
///
/// `encrypted_key_b64` is the raw base64 string (the JSON field value bytes).
/// Chrome stores `base64("DPAPI" + dpapi_blob)`, so this base64-decodes the input
/// and strips the mandatory 5-byte `DPAPI` prefix, returning the DPAPI blob ready
/// for [`decrypt_local_state_key`].
///
/// Errors loudly — malformed base64 ([`DpapiError::Base64Error`]) or a missing
/// `DPAPI` prefix ([`DpapiError::MissingDpapiPrefix`], which names the bytes that
/// were actually present) — rather than guessing.
pub fn parse_local_state_encrypted_key(_encrypted_key_b64: &[u8]) -> Result<Vec<u8>, DpapiError> {
    // RED stub: not implemented. Returns an empty blob so downstream decode fails
    // a value check rather than fabricating output.
    Ok(Vec::new())
}

/// Decrypt a Chrome/Edge `Local State` cookie key from its DPAPI blob bytes.
///
/// `blob_bytes` is the inner DPAPI blob (post [`parse_local_state_encrypted_key`]).
/// `master_key` is the 64-byte user master key (from `masterkey.rs`). Parses the
/// blob, decrypts it with the master key (no entropy), and requires the recovered
/// plaintext to be exactly the 32-byte AES-256 cookie key.
///
/// A wrong/absent master key fails the blob's Sign-HMAC and returns a
/// [`DpapiError`] — it never returns garbage or a fabricated key. A plaintext of
/// the wrong length is rejected with [`DpapiError::UnexpectedKeyLength`].
pub fn decrypt_local_state_key(
    _blob_bytes: &[u8],
    _master_key: &[u8],
) -> Result<[u8; 32], DpapiError> {
    // RED stub: not implemented. Returns a zero key (deliberately wrong) so the
    // oracle value-match test FAILS; it does NOT fabricate a plausible key.
    Ok([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into bytes (test helper).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // --- impacket 0.13.1 oracle vector (provenance: tests/data/README.md) ---
    // Master key = the tier-1 impacket-validated key from decrypt.rs.
    const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
    // The `Local State` `encrypted_key` (base64 of "DPAPI" + this DPAPI blob).
    // Minted + confirmed by impacket DPAPI_BLOB.decrypt -> COOKIE_KEY below.
    const LOCAL_STATE_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc60000000002000000000010660000000100002000000000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff000000000e80000000020000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000fadff9dbad57d443d7a0d77cf9fbfdd68827ce91b2ca6ff533bf2f7467ce329865d99ceb7b841f271e14d1f508ce3a2c40000000fe727776259faf7d3100849fb4ea49fc69fc16bebd1ec98b5a5227b4cfafbce2983ff94a57afd2f2ba1f9afa32ae3aa2148c10f2f3016ccabc3e71c6f26dd6c0";
    // base64("DPAPI" + LOCAL_STATE_BLOB) — the exact `os_crypt.encrypted_key` string.
    const ENCRYPTED_KEY_B64: &str = "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAAz8Z9e40C+SoouK05ivQzGAAAAAAIAAAAAABBmAAAAAQAAIAAAAAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/AAAAAA6AAAAAAgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAA+t/5261X1EPXoNd8+fv91ognzpGyym/1M78vdGfOMphl2Zzre4QfJx4U0fUIzjosQAAAAP5yd3Yln699MQCEn7TqSfxp/Ba+vR7Ji1pSJ7TPr7zimD/5Slev0vK6H5r6Mq46ohSMEPLzAWzKvD5xxvJt1sA=";
    // The 32-byte cookie key impacket recovers from the blob (bytes 0x20..0x3f).
    const COOKIE_KEY_HEX: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    // A `v10` cookie produced with COOKIE_KEY: "v10" + nonce(12) + GCM(ct||tag).
    const V10_COOKIE_HEX: &str = "7631300102030405060708090a0b0c1b5af334ffe7a1fe676c5ab453c8848232ab94aa630c69bae71883958ba23e4dfe4cc5faff526ce54b";
    const V10_PLAINTEXT: &[u8] = b"forensic-session-token-42";

    // RED: base64-decode + strip "DPAPI" must yield the exact DPAPI blob bytes.
    #[test]
    fn local_state_b64_strips_dpapi_prefix_to_blob() {
        let blob =
            parse_local_state_encrypted_key(ENCRYPTED_KEY_B64.as_bytes()).expect("decode ok");
        assert_eq!(blob, hex(LOCAL_STATE_BLOB_HEX));
    }

    // RED: the recovered cookie key must equal impacket's 32-byte plaintext.
    #[test]
    fn decrypt_local_state_key_matches_impacket() {
        let blob = hex(LOCAL_STATE_BLOB_HEX);
        let mk = hex(MASTER_KEY_HEX);
        let key = decrypt_local_state_key(&blob, &mk).expect("decrypt ok");
        assert_eq!(key.to_vec(), hex(COOKIE_KEY_HEX));
    }

    // RED: full chain — Local State key then v10 cookie -> known plaintext.
    #[test]
    fn end_to_end_local_state_then_v10_cookie() {
        let blob =
            parse_local_state_encrypted_key(ENCRYPTED_KEY_B64.as_bytes()).expect("decode ok");
        let mk = hex(MASTER_KEY_HEX);
        let key = decrypt_local_state_key(&blob, &mk).expect("decrypt ok");

        let raw = hex(V10_COOKIE_HEX);
        let enc = detect_chrome_cookie_encoding(&raw);
        let ChromeCookieEncoding::V10 { nonce, ciphertext } = enc else {
            panic!("expected v10 encoding");
        };
        let plaintext = decrypt_v10_cookie(&nonce, &ciphertext, &key).expect("gcm ok");
        assert_eq!(plaintext, V10_PLAINTEXT);
    }

    // RED: refuse, don't fabricate — a good blob with NO usable master key (an
    // all-zero key) must fail the Sign-HMAC and error, never return a key.
    #[test]
    fn no_usable_master_key_refuses_rather_than_fabricates() {
        let blob = hex(LOCAL_STATE_BLOB_HEX);
        let bad_mk = [0u8; 64];
        let result = decrypt_local_state_key(&blob, &bad_mk);
        assert!(
            result.is_err(),
            "must error on an unusable master key, never fabricate a cookie key"
        );
    }

    #[test]
    fn detect_v10_prefix() {
        let mut data = vec![0u8; 20];
        data[0..3].copy_from_slice(b"v10");
        let enc = detect_chrome_cookie_encoding(&data);
        assert!(matches!(enc, ChromeCookieEncoding::V10 { .. }));
    }

    #[test]
    fn detect_v20_prefix() {
        let mut data = vec![0u8; 20];
        data[0..3].copy_from_slice(b"v20");
        let enc = detect_chrome_cookie_encoding(&data);
        assert!(matches!(enc, ChromeCookieEncoding::V20 { .. }));
    }

    #[test]
    fn detect_dpapi_prefix() {
        let data = b"DPAPI\x00\x01\x02\x03".to_vec();
        let enc = detect_chrome_cookie_encoding(&data);
        assert!(matches!(enc, ChromeCookieEncoding::DpapiBlob(_)));
    }

    #[test]
    fn detect_plaintext_is_raw() {
        let enc = detect_chrome_cookie_encoding(b"plaintext_value");
        assert_eq!(enc, ChromeCookieEncoding::Raw);
    }

    #[test]
    #[allow(deprecated)]
    fn decrypt_v10_roundtrip() {
        use aes_gcm::{
            aead::{Aead, Nonce},
            Aes256Gcm, KeyInit,
        };
        let key = [0x42u8; 32];
        let nonce_bytes = [0x11u8; 12];
        let plaintext = b"session_token_value";
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        #[allow(deprecated)]
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let recovered = decrypt_v10_cookie(&nonce_bytes, &ciphertext, &key).expect("ok");
        assert_eq!(recovered, plaintext);
    }
}
