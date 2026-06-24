//! Windows **Wi-Fi** (`Wlansvc`) WPA/WPA2 PSK decoder.
//!
//! WLAN profiles live at
//! `%PROGRAMDATA%\Microsoft\Wlansvc\Profiles\Interfaces\<GUID>\<GUID>.xml`. A
//! protected profile stores the pre-shared key in `<keyMaterial>` as the
//! **hex-encoded bytes of a DPAPI blob**, protected by the SYSTEM (`Wlansvc`)
//! master key. Decrypting it yields the PSK as a UTF-8 string terminated with a
//! NUL.
//!
//! This module owns the hex-decode + PSK extraction; the DPAPI decrypt reuses
//! [`crate::decrypt::decrypt_dpapi_blob`] (RustCrypto, no hand-rolled crypto). A
//! thin [`extract_key_material`] helper pulls the `<keyMaterial>` text out of the
//! profile XML so callers need no XML parser, but the PSK decode is the core and
//! takes the hex directly.

use crate::error::DpapiError;

/// Extract the `<keyMaterial>` hex text from a WLAN profile XML, if present.
///
/// A minimal, robust scan for the first `<keyMaterial>...</keyMaterial>` element
/// (the profile schema has exactly one). Returns `None` when the tag is absent
/// (e.g. an open network with no key). Whitespace around the value is trimmed.
pub fn extract_key_material(profile_xml: &str) -> Option<&str> {
    const OPEN: &str = "<keyMaterial>";
    const CLOSE: &str = "</keyMaterial>";
    let start = profile_xml.find(OPEN)? + OPEN.len();
    let rest = profile_xml.get(start..)?;
    let end = rest.find(CLOSE)?;
    Some(rest.get(..end)?.trim())
}

/// Decrypt a WLAN `<keyMaterial>` hex string into the plaintext PSK.
///
/// `key_material_hex` is the hex text from `<keyMaterial>` (case-insensitive).
/// `master_key` is the 64-byte SYSTEM (`Wlansvc`) master key. Hex-decodes to the
/// DPAPI blob, decrypts it (no entropy) via [`crate::decrypt::decrypt_dpapi_blob`],
/// strips the trailing NUL, and UTF-8-decodes the PSK.
///
/// A wrong/absent master key fails the blob's Sign-HMAC and returns a
/// [`DpapiError`] — it never returns a fabricated/empty PSK.
pub fn decrypt_wlan_key_material(
    key_material_hex: &str,
    master_key: &[u8],
) -> Result<String, DpapiError> {
    let blob_bytes = hex_decode(key_material_hex)?;
    let blob = crate::blob::parse_dpapi_blob(&blob_bytes)?;
    let cleartext = crate::decrypt::decrypt_dpapi_blob(&blob, master_key, None)?;
    // Windows stores the PSK as UTF-8 with a trailing NUL.
    let trimmed = cleartext
        .iter()
        .position(|&b| b == 0)
        .map_or(cleartext.as_slice(), |nul| &cleartext[..nul]);
    String::from_utf8(trimmed.to_vec()).map_err(|_| DpapiError::Utf16Error)
}

/// Decode an ASCII hex string into bytes. Rejects odd length or non-hex digits
/// loudly (with the offending value range) rather than guessing.
fn hex_decode(s: &str) -> Result<Vec<u8>, DpapiError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(DpapiError::InvalidHex(format!(
            "odd length ({} chars)",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

/// Convert one ASCII hex digit to its nibble; non-hex bytes error with the value.
fn hex_nibble(b: u8) -> Result<u8, DpapiError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(DpapiError::InvalidHex(format!("non-hex byte {other:#04x}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- impacket 0.13.1 oracle vector (provenance: tests/data/README.md,
    // reproducer tests/data/build_wifi_vector.py) ---
    const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
    // A WLAN <keyMaterial> hex (the DPAPI blob over the PSK + NUL), as stored.
    const KEY_MATERIAL_HEX: &str = "01000000D08C9DDF0115D1118C7A00C04FC297EB0100000033F19F5EE340BE4A8A2E2B4E62BD0CC600000000020000000000106600000001000020000000DEADBEEFCAFEBABE0011223344556677DEADBEEFCAFEBABE0011223344556677000000000E8000000002000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000051E2C9E20723EF48230A95FCEBBA31AF8BC567EDABBBD958F6E42E4CCE9236C240000000538815E34921B886D09A9CEAD4024E596A73C9C3B53E37A4481D05D7097751049323C613F78C8BD0D8A3AAAB8BF9FBC966E87526245734D0C781DFE0214B1D70";
    const EXPECT_PSK: &str = "CorrectHorseBatteryStaple";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RED: the keyMaterial hex decrypts to impacket's plaintext PSK.
    #[test]
    fn decrypt_wlan_key_material_matches_impacket() {
        let mk = hex(MASTER_KEY_HEX);
        let psk = decrypt_wlan_key_material(KEY_MATERIAL_HEX, &mk).expect("decrypt ok");
        assert_eq!(psk, EXPECT_PSK);
    }

    // RED: the thin XML helper extracts the keyMaterial text.
    #[test]
    fn extract_key_material_from_profile_xml() {
        let xml = format!(
            "<WLANProfile><MSM><security><sharedKey>\
             <keyMaterial>{KEY_MATERIAL_HEX}</keyMaterial>\
             </sharedKey></security></MSM></WLANProfile>"
        );
        let km = extract_key_material(&xml).expect("keyMaterial present");
        assert_eq!(km, KEY_MATERIAL_HEX);
    }

    // RED: end-to-end — XML → keyMaterial → PSK.
    #[test]
    fn end_to_end_profile_xml_to_psk() {
        let xml = format!(
            "<WLANProfile><MSM><security><sharedKey>\
             <keyMaterial>\n  {KEY_MATERIAL_HEX}\n  </keyMaterial>\
             </sharedKey></security></MSM></WLANProfile>"
        );
        let km = extract_key_material(&xml).expect("keyMaterial present");
        let mk = hex(MASTER_KEY_HEX);
        let psk = decrypt_wlan_key_material(km, &mk).expect("decrypt ok");
        assert_eq!(psk, EXPECT_PSK);
    }

    // RED: refuse, don't fabricate — no usable master key (all-zero) must error.
    #[test]
    fn no_usable_master_key_refuses_rather_than_fabricates() {
        let bad_mk = [0u8; 64];
        let result = decrypt_wlan_key_material(KEY_MATERIAL_HEX, &bad_mk);
        assert!(
            result.is_err(),
            "must error on an unusable master key, never fabricate a PSK"
        );
    }
}
