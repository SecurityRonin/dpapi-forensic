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
use crate::error::DpapiError::TooShort;

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
    let mut pos = 0usize;
    let _version = read_u32(data, &mut pos);
    pos = pos.saturating_add(16); // Guid
    let desc_len = read_u32(data, &mut pos) as usize;
    pos = advance(pos, desc_len, data.len())?; // Description
    pos = advance(pos, 12, data.len())?; // Unknown
    let _size = read_u32(data, &mut pos); // Size
    pos = advance(pos, 32, data.len())?; // Guid2 + Guid3
    let key_size = read_u32(data, &mut pos) as usize;
    let end = pos.checked_add(key_size).ok_or(too_short(data.len()))?;
    let blob = data.get(pos..end).ok_or(TooShort {
        needed: end,
        got: data.len(),
    })?;
    Ok(blob.to_vec())
}

/// Decrypt the VPOL policy blob with the master key → the two AES keys.
///
/// `vpol_blob` is the inner DPAPI blob (post [`parse_vpol_file`]). A wrong/absent
/// master key fails the blob's Sign-HMAC and returns a [`DpapiError`] — it never
/// returns guessed keys.
pub fn decrypt_vpol_keys(vpol_blob: &[u8], master_key: &[u8]) -> Result<VaultVpolKeys, DpapiError> {
    let blob = crate::blob::parse_dpapi_blob(vpol_blob)?;
    let cleartext = crate::decrypt::decrypt_dpapi_blob(&blob, master_key, None)?;
    // VAULT_VPOL_KEYS = Key1(BCRYPT_KEY_WRAP) || Key2(BCRYPT_KEY_WRAP).
    let mut pos = 0usize;
    let key1 = read_bcrypt_key(&cleartext, &mut pos)?;
    let key2 = read_bcrypt_key(&cleartext, &mut pos)?;
    Ok(VaultVpolKeys { key1, key2 })
}

/// Read one impacket `BCRYPT_KEY_WRAP` at `*pos` and return its raw AES key.
///
/// Layout: `Size(4) Version(4) Unknown2(4)` then a `BCRYPT_KEY_DATA_BLOB_HEADER`
/// (`dwMagic(4) dwVersion(4) cbKeyData(4) bKey(cbKeyData)`). The wrap's `Size`
/// field over-states the inner blob length (impacket counts 8 padding bytes the
/// nested struct does not consume), so `*pos` is advanced by the *actual* header
/// consumption (`12 + 12 + cbKeyData`), not by `Size` — keeping the two keys
/// correctly delimited regardless of that quirk.
fn read_bcrypt_key(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, DpapiError> {
    let _size = read_u32(data, pos);
    let _version = read_u32(data, pos);
    let _unknown2 = read_u32(data, pos);
    // BCRYPT_KEY_DATA_BLOB_HEADER: dwMagic(4) dwVersion(4) cbKeyData(4) bKey(cbKeyData).
    let _magic = read_u32(data, pos);
    let _hver = read_u32(data, pos);
    let cb = read_u32(data, pos) as usize;
    let key_end = pos.checked_add(cb).ok_or(too_short(data.len()))?;
    let key = data.get(*pos..key_end).ok_or(TooShort {
        needed: key_end,
        got: data.len(),
    })?;
    *pos = key_end;
    Ok(key.to_vec())
}

/// Parse a `VAULT_VCRD` record into its encrypted attributes.
pub fn parse_vcrd_attributes(vcrd: &[u8]) -> Result<Vec<VcrdAttribute>, DpapiError> {
    // Header: SchemaGuid(16) Unknown0(4) LastWritten(8) Unknown1(4) Unknown2(4)
    //         FriendlyNameLen(4) FriendlyName(var) AttributesMapsSize(4) AttributeMaps(var)
    let mut pos = 0usize;
    pos = advance(pos, 16 + 4 + 8 + 4 + 4, vcrd.len())?;
    let fn_len = read_u32(vcrd, &mut pos) as usize;
    pos = advance(pos, fn_len, vcrd.len())?;
    let maps_size = read_u32(vcrd, &mut pos) as usize;
    let maps_start = pos;
    let maps_end = maps_start
        .checked_add(maps_size)
        .ok_or(too_short(vcrd.len()))?;
    // Each map entry: Id(4) Offset(4) Unknown1(4) = 12 bytes. Offsets are absolute
    // into the whole record; each attribute runs to the next entry's offset (or EOF).
    const MAP_ENTRY: usize = 12;
    if maps_size % MAP_ENTRY != 0 {
        return Err(too_short(vcrd.len()));
    }
    let count = maps_size / MAP_ENTRY;
    let mut offsets: Vec<(u32, usize)> = Vec::with_capacity(count);
    let mut mp = maps_start;
    for _ in 0..count {
        let id = read_u32(vcrd, &mut mp);
        let offset = read_u32(vcrd, &mut mp) as usize;
        let _unknown1 = read_u32(vcrd, &mut mp);
        offsets.push((id, offset));
    }
    if mp > maps_end {
        return Err(too_short(vcrd.len()));
    }

    let mut attrs = Vec::with_capacity(count);
    for i in 0..count {
        let (id, start) = offsets[i];
        let end = offsets.get(i + 1).map_or(vcrd.len(), |&(_, o)| o);
        let attr_bytes = vcrd.get(start..end).ok_or(TooShort {
            needed: end,
            got: vcrd.len(),
        })?;
        if let Some((iv, payload)) = parse_attribute_payload(attr_bytes) {
            attrs.push(VcrdAttribute {
                id,
                iv,
                data: payload,
            });
        }
    }
    Ok(attrs)
}

/// Extract `(IV, Data)` from one `VAULT_ATTRIBUTE`'s raw bytes (impacket layout).
///
/// Returns `None` for attributes too small to carry an encrypted payload (the
/// impacket example skips attributes whose length is `<= 28`). The fixed prefix is
/// `Id(4) Unknown1(4) Unknown2(4) Unknown3(4)` (16 bytes), then an optional 6-byte
/// `Pad` when bytes `[16..22]` are zero, then an optional 4-byte `Unknown5` when
/// `Id >= 100`, then `Size(4) IVPresent(1) IVSize(4) IV[IVSize] Data[...]`.
fn parse_attribute_payload(attr: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if attr.len() <= 28 {
        return None;
    }
    let id = u32::from_le_bytes(attr.get(0..4)?.try_into().ok()?);
    let mut pos = 16usize;
    if attr.get(16..22)? == [0u8; 6] {
        pos += 6; // Pad
    }
    if id >= 100 {
        pos += 4; // Unknown5
    }
    let size = u32::from_le_bytes(attr.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    let iv_present = *attr.get(pos)?;
    pos += 1;
    let iv_size = u32::from_le_bytes(attr.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    let (iv, data_len) = if iv_present != 0 {
        let iv = attr.get(pos..pos + iv_size)?.to_vec();
        pos += iv_size;
        (iv, size.checked_sub(iv_size + 5)?)
    } else {
        (Vec::new(), size.checked_sub(1)?)
    };
    let data = attr.get(pos..pos + data_len)?.to_vec();
    Some((iv, data))
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
    use aes::Aes256;
    use cbc::Decryptor as CbcDec;
    use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};

    let zero_iv = [0u8; 16];
    let iv: &[u8] = if attr.iv.len() == 16 {
        &attr.iv
    } else {
        &zero_iv
    };
    let mut buf = attr.data.clone();
    let dec = CbcDec::<Aes256>::new_from_slices(vpol_key, iv)
        .map_err(|_| DpapiError::InvalidKeyLength)?;
    let out = dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| DpapiError::DecryptionFailed)?;
    Ok(out.to_vec())
}

/// Parse a decrypted `VAULT_INTERNET_EXPLORER` cleartext into a [`WebCredential`].
///
/// Layout: `Version(4) Count(4) Unknown(4)` then three `Id(4) Len(4) Value(Len)`
/// triples (Username, Resource, Password), each UTF-16LE.
pub fn parse_internet_explorer(cleartext: &[u8]) -> Result<WebCredential, DpapiError> {
    let mut pos = 12usize; // Version + Count + Unknown
    let username = read_id_len_utf16(cleartext, &mut pos)?;
    let resource = read_id_len_utf16(cleartext, &mut pos)?;
    let password = read_id_len_utf16(cleartext, &mut pos)?;
    Ok(WebCredential {
        username,
        resource,
        password,
    })
}

/// Read an `Id(4) Len(4) Value(Len)` triple at `*pos` and UTF-16LE-decode `Value`.
fn read_id_len_utf16(data: &[u8], pos: &mut usize) -> Result<String, DpapiError> {
    let _id = read_u32(data, pos);
    let len = read_u32(data, pos) as usize;
    let end = pos.checked_add(len).ok_or(too_short(data.len()))?;
    let slice = data.get(*pos..end).ok_or(TooShort {
        needed: end,
        got: data.len(),
    })?;
    *pos = end;
    Ok(decode_utf16le(slice))
}

/// Read a little-endian u32 at `*pos`, advancing by 4; out-of-range yields 0.
#[inline]
fn read_u32(data: &[u8], pos: &mut usize) -> u32 {
    let v = data
        .get(*pos..*pos + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes);
    *pos = pos.saturating_add(4);
    v
}

/// Advance `pos` by `n`, erroring if it would exceed `len`.
fn advance(pos: usize, n: usize, len: usize) -> Result<usize, DpapiError> {
    let end = pos.checked_add(n).ok_or(too_short(len))?;
    if end > len {
        return Err(TooShort {
            needed: end,
            got: len,
        });
    }
    Ok(end)
}

/// Build a `TooShort` error with `needed = usize::MAX` (overflow guard sentinel).
#[inline]
fn too_short(got: usize) -> DpapiError {
    TooShort {
        needed: usize::MAX,
        got,
    }
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
    const VPOL_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc6000000000200000000001066000000010000200000001122334455667788112233445566778811223344556677881122334455667788000000000e8000000002000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000065a02b0acc4ef1fb8f698d7e6c9214d19144177556a964a02b9c13445d8cb6b640779e5cf1e273f2f8ede6445631e12c28c81e907373f71b9d26ffca96bba17b5147feb3b70fb9ebe9aa4150a1ec63c1f4e7356e600ed1bb5c15b2f850b8f21b3fac4e658821cf41f8b779baa815284576fa06d4aa59509eb7541d331958e7ca4000000057da67b85c3f524f46e18fd82b0bcfedba543efe03877d8f7d81daef61e311df7f8509d7ee7cd25becdfac53fa47c20a4150417065518659c72f200da584e654";
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
