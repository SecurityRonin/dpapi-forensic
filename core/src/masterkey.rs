//! DPAPI **master-key file** parser + user master-key derivation.
//!
//! This is the on-disk counterpart of the LSASS master-key source: the same
//! 64-byte master key that [`crate::decrypt_dpapi_blob`] consumes, but recovered
//! from a master-key *file* (`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`) plus the
//! user's password (or pre-hashed SHA1), rather than read from LSASS memory.
//!
//! Layout and crypto follow impacket's `MasterKeyFile` / `MasterKey.decrypt`
//! (impacket 0.13.1, `impacket/dpapi.py`). The master-key file is:
//!
//! * a fixed 128-byte header — `Version(4)`, `unk1(4)`, `unk2(4)`, `Guid(72,
//!   UTF-16LE)`, `Unknown(4)`, `Policy(4)`, `Flags(4)`, then four `<u64` length
//!   fields: `MasterKeyLen`, `BackupKeyLen`, `CredHistLen`, `DomainKeyLen`;
//! * followed by the four sub-blobs in that order, each exactly its length.
//!
//! The **`MasterKey`** sub-blob is itself `Version(4)`, `Salt(16)`,
//! `IterationCount(4)`, `HashAlgo(4)`, `CryptAlgo(4)`, then the encrypted `data`.
//!
//! Derivation (`MasterKey.decrypt`): `deriveKey(preKey, salt, keyLen+ivLen,
//! rounds, prf=HMAC_H)` — impacket's iterated XOR construction, NOT standard
//! PBKDF2 — yields `cryptKey || iv`; CBC-decrypt `data`; the trailing 64 bytes are
//! the master key, the leading 16 are `hmacSalt`, and the next `digestLen` bytes
//! are an HMAC verified via `HMAC_H(HMAC_H(preKey, hmacSalt), masterKey)`.
//!
//! The pre-key for the user path is
//! `HMAC-SHA1(SHA1(UTF16LE(password)), UTF16LE(sid + "\0"))`
//! (impacket `deriveKeysFromUser`, SHA1 variant).
//!
//! All cryptography uses audited RustCrypto crates — no hand-rolled primitives.

use aes::Aes256;
use cbc::Decryptor as CbcDec;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

use forensicnomicon::dpapi::{
    cipher_alg_info, hash_alg_info, CALG_AES_256, CALG_HMAC, CALG_SHA1, CALG_SHA_512,
};

use crate::blob::{decode_utf16le, hash_alg};
use crate::decrypt::hmac_hash;
use crate::error::DpapiError;

/// Fixed master-key file header size (impacket `len(MasterKeyFile)`).
const HEADER_LEN: usize = 128;
/// Size of the decrypted DPAPI master key consumed by blob decryption.
pub const MASTER_KEY_LEN: usize = 64;

/// A parsed DPAPI master-key file, mirroring impacket's `MasterKeyFile`.
///
/// The four sub-blobs are exposed as owned byte vectors (each may be empty when
/// its length field is zero). `master_key` is the only one needed for the user
/// password path; `domain_key` feeds the (not-yet-implemented) RSA backup path.
#[derive(Debug, Clone)]
pub struct MasterKeyFile {
    pub version: u32,
    /// The key GUID as stored (UTF-16LE, NUL-trimmed) — matches the file name.
    pub guid: String,
    pub policy: u32,
    pub flags: u32,
    pub master_key: Vec<u8>,
    pub backup_key: Vec<u8>,
    pub cred_hist: Vec<u8>,
    pub domain_key: Vec<u8>,
}

/// The `MasterKey` sub-blob: salt + rounds + alg IDs + encrypted payload.
#[derive(Debug, Clone)]
pub struct MasterKey {
    pub version: u32,
    pub salt: [u8; 16],
    pub rounds: u32,
    pub alg_id_hash: u32,
    pub alg_id_encrypt: u32,
    pub data: Vec<u8>,
}

/// Read a little-endian `u32` at `*pos`, advancing by 4. Out-of-range → error.
fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, DpapiError> {
    let slice: [u8; 4] = data
        .get(*pos..*pos + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(DpapiError::TooShort {
            needed: *pos + 4,
            got: data.len(),
        })?;
    *pos += 4;
    Ok(u32::from_le_bytes(slice))
}

/// Read a little-endian `u64` at `*pos`, advancing by 8. Out-of-range → error.
fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, DpapiError> {
    let slice: [u8; 8] = data
        .get(*pos..*pos + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or(DpapiError::TooShort {
            needed: *pos + 8,
            got: data.len(),
        })?;
    *pos += 8;
    Ok(u64::from_le_bytes(slice))
}

/// Parse a DPAPI master-key file (impacket `MasterKeyFile` layout).
///
/// Validates the 128-byte header is present and that the four declared sub-blob
/// lengths fit the buffer; a truncated file is rejected loudly with the byte
/// counts rather than silently yielding a short sub-blob.
pub fn parse_masterkey_file(data: &[u8]) -> Result<MasterKeyFile, DpapiError> {
    if data.len() < HEADER_LEN {
        return Err(DpapiError::TooShort {
            needed: HEADER_LEN,
            got: data.len(),
        });
    }

    let mut pos = 0usize;
    let version = read_u32(data, &mut pos)?;
    let _unk1 = read_u32(data, &mut pos)?;
    let _unk2 = read_u32(data, &mut pos)?;
    let guid = decode_utf16le(&data[pos..pos + 72]);
    pos += 72;
    let _unknown = read_u32(data, &mut pos)?;
    let policy = read_u32(data, &mut pos)?;
    let flags = read_u32(data, &mut pos)?;
    let master_key_len = read_u64(data, &mut pos)? as usize;
    let backup_key_len = read_u64(data, &mut pos)? as usize;
    let cred_hist_len = read_u64(data, &mut pos)? as usize;
    let domain_key_len = read_u64(data, &mut pos)? as usize;
    debug_assert_eq!(pos, HEADER_LEN);

    let mut take = |len: usize| -> Result<Vec<u8>, DpapiError> {
        let slice = data.get(pos..pos + len).ok_or(DpapiError::TooShort {
            needed: pos + len,
            got: data.len(),
        })?;
        pos += len;
        Ok(slice.to_vec())
    };

    let master_key = take(master_key_len)?;
    let backup_key = take(backup_key_len)?;
    let cred_hist = take(cred_hist_len)?;
    let domain_key = take(domain_key_len)?;

    Ok(MasterKeyFile {
        version,
        guid,
        policy,
        flags,
        master_key,
        backup_key,
        cred_hist,
        domain_key,
    })
}

/// Parse the `MasterKey` sub-blob (impacket `MasterKey` structure).
pub fn parse_master_key(data: &[u8]) -> Result<MasterKey, DpapiError> {
    // Version(4) + Salt(16) + Rounds(4) + HashAlgo(4) + CryptAlgo(4) = 32.
    if data.len() < 32 {
        return Err(DpapiError::TooShort {
            needed: 32,
            got: data.len(),
        });
    }
    let mut pos = 0usize;
    let version = read_u32(data, &mut pos)?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[pos..pos + 16]);
    pos += 16;
    let rounds = read_u32(data, &mut pos)?;
    let alg_id_hash = read_u32(data, &mut pos)?;
    let alg_id_encrypt = read_u32(data, &mut pos)?;
    let payload = data[pos..].to_vec();
    Ok(MasterKey {
        version,
        salt,
        rounds,
        alg_id_hash,
        alg_id_encrypt,
        data: payload,
    })
}

/// Whether the master-key sub-blob's hash module is SHA-512 (vs SHA-1).
///
/// Per impacket `MasterKey.decrypt`: `CALG_HMAC` (0x8009) forces the SHA-1
/// module; every other recognised `HashAlgo` uses its table module — SHA-512 for
/// `CALG_SHA_512` (0x800e), SHA-1 for `CALG_SHA` (0x8004).
fn uses_sha512(alg_id_hash: u32) -> Result<bool, DpapiError> {
    if alg_id_hash == CALG_HMAC {
        return Ok(false);
    }
    hash_alg_info(alg_id_hash)
        .map(|h| h.is_sha512)
        .ok_or(DpapiError::UnsupportedAlgId(alg_id_hash))
}

/// PRF = HMAC over the chosen hash module (SHA-512 vs SHA-1).
///
/// Delegates the RustCrypto HMAC wiring to [`crate::decrypt::hmac_hash`] — the
/// same construction the blob decryptor uses — selecting the module via the
/// canonical `algId` for the chosen width so a single keyed-HMAC implementation
/// serves both the on-disk (master-key file) and in-memory (blob) paths.
fn prf(is_sha512: bool, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let alg = hash_alg(if is_sha512 { CALG_SHA_512 } else { CALG_SHA1 });
    hmac_hash(alg, key, msg)
}

/// impacket `MasterKey.deriveKey`: iterated key material of length `keylen`.
///
/// For each block `i = 1..`: `derived = prf(passphrase, salt || BE32(i))`, then
/// repeated `count-1` times `derived ^= prf(passphrase, derived)` (full-width
/// little-endian XOR of equal-length digests). Blocks are concatenated until at
/// least `keylen` bytes, then truncated. This is the DPAPI variant, distinct from
/// standard PBKDF2.
fn derive_key(
    is_sha512: bool,
    passphrase: &[u8],
    salt: &[u8],
    keylen: usize,
    count: u32,
) -> Result<Vec<u8>, DpapiError> {
    let mut key_material: Vec<u8> = Vec::with_capacity(keylen + 64);
    let mut i: u32 = 1;
    while key_material.len() < keylen {
        let mut u = salt.to_vec();
        u.extend_from_slice(&i.to_be_bytes());
        i += 1;
        let mut derived = prf(is_sha512, passphrase, &u)?;
        for _ in 0..count.saturating_sub(1) {
            let actual = prf(is_sha512, passphrase, &derived)?;
            for (d, a) in derived.iter_mut().zip(actual.iter()) {
                *d ^= a;
            }
        }
        key_material.extend_from_slice(&derived);
    }
    key_material.truncate(keylen);
    Ok(key_material)
}

/// Derive the 64-byte master key from a master-key sub-blob and a **pre-key**.
///
/// `pre_key` is the per-user pre-key (impacket's `deriveKeysFromUser` output for
/// the password path, or LSA `UserKey`/`MachineKey` for the SYSTEM path). Mirrors
/// impacket `MasterKey.decrypt`: derive `cryptKey || iv`, CBC-decrypt, take the
/// trailing 64 bytes, and verify the embedded HMAC; an HMAC mismatch (wrong
/// pre-key) is rejected with [`DpapiError::HmacMismatch`] rather than returning
/// garbage.
pub fn derive_master_key_from_prekey(
    mk: &MasterKey,
    pre_key: &[u8],
) -> Result<[u8; MASTER_KEY_LEN], DpapiError> {
    let is_sha512 = uses_sha512(mk.alg_id_hash)?;
    let cipher = cipher_alg_info(mk.alg_id_encrypt)
        .ok_or(DpapiError::UnsupportedAlgId(mk.alg_id_encrypt))?;
    let digest_len = hash_alg_info(mk.alg_id_hash)
        .ok_or(DpapiError::UnsupportedAlgId(mk.alg_id_hash))?
        .digest_len;

    let derived = derive_key(
        is_sha512,
        pre_key,
        &mk.salt,
        cipher.key_len + cipher.iv_len,
        mk.rounds,
    )?;
    let crypt_key = &derived[..cipher.key_len];
    let iv = &derived[cipher.key_len..cipher.key_len + cipher.iv_len];

    let cleartext = if mk.alg_id_encrypt == CALG_AES_256 {
        cbc_decrypt_no_pad::<Aes256>(crypt_key, iv, &mk.data)?
    } else {
        cbc_decrypt_no_pad::<TdesEde3>(crypt_key, iv, &mk.data)?
    };

    if cleartext.len() < MASTER_KEY_LEN || cleartext.len() < 16 + digest_len {
        return Err(DpapiError::DecryptionFailed);
    }
    let master_key_bytes = &cleartext[cleartext.len() - MASTER_KEY_LEN..];
    let hmac_salt = &cleartext[..16];
    let stored_hmac = &cleartext[16..16 + digest_len];

    // hmacKey = HMAC_H(preKey, hmacSalt); calc = HMAC_H(hmacKey, masterKey)
    let hmac_key = prf(is_sha512, pre_key, hmac_salt)?;
    let calc = prf(is_sha512, &hmac_key, master_key_bytes)?;
    if calc.get(..digest_len) != Some(stored_hmac) {
        return Err(DpapiError::HmacMismatch);
    }

    let mut out = [0u8; MASTER_KEY_LEN];
    out.copy_from_slice(master_key_bytes);
    Ok(out)
}

/// CBC-decrypt without unpadding (the DPAPI master-key payload is block-aligned
/// and carries no PKCS#7 padding — the structure, not a pad byte, bounds it).
fn cbc_decrypt_no_pad<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError>
where
    C: cipher::BlockCipher + cipher::BlockDecryptMut + cipher::KeyInit + cipher::BlockSizeUser,
{
    let mut buf = ciphertext.to_vec();
    let dec = CbcDec::<C>::new_from_slices(key, iv).map_err(|_| DpapiError::InvalidKeyLength)?;
    let out = dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| DpapiError::DecryptionFailed)?;
    Ok(out.to_vec())
}

/// Derive the per-user **pre-key** from a SID and a pre-hashed SHA-1 password.
///
/// `pwd_sha1` is `SHA1(UTF16LE(password))`. Returns
/// `HMAC-SHA1(pwd_sha1, UTF16LE(sid + "\0"))` — impacket `deriveKeysFromUser`
/// key1 (the SHA-1 variant). This is the value to pass to
/// [`derive_master_key_from_prekey`] for a modern (Vista+) profile.
pub fn prekey_from_sha1(sid: &str, pwd_sha1: &[u8; 20]) -> Result<[u8; 20], DpapiError> {
    let sid_utf16 = utf16le_with_nul(sid);
    let mut mac =
        Hmac::<Sha1>::new_from_slice(pwd_sha1).map_err(|_| DpapiError::InvalidKeyLength)?;
    mac.update(&sid_utf16);
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 20];
    k.copy_from_slice(&out);
    Ok(k)
}

/// Derive the pre-key directly from a plaintext password and SID.
///
/// `pwd_sha1 = SHA1(UTF16LE(password))`, then [`prekey_from_sha1`].
pub fn prekey_from_password(sid: &str, password: &str) -> Result<[u8; 20], DpapiError> {
    let mut h = Sha1::new();
    h.update(utf16le(password));
    let digest: [u8; 20] = h.finalize().into();
    prekey_from_sha1(sid, &digest)
}

/// Full user-password path: parse the file, derive the pre-key, decrypt the key.
///
/// Convenience over the sub-steps for the common case (a single master-key file
/// + the user's password). Returns the 64-byte master key on success.
pub fn derive_master_key_from_password(
    file: &MasterKeyFile,
    sid: &str,
    password: &str,
) -> Result<[u8; MASTER_KEY_LEN], DpapiError> {
    let mk = parse_master_key(&file.master_key)?;
    let pre_key = prekey_from_password(sid, password)?;
    derive_master_key_from_prekey(&mk, &pre_key)
}

/// Decrypt the master key via the **domain RSA backup key** (`DomainKey` sub-blob).
///
/// Next sub-step, not implemented this pass: the `DomainKey` sub-blob holds the
/// master key wrapped with the domain controller's RSA *backup* key (the
/// `DPAPI_DOMAIN_RSA_MASTER_KEY` structure, decrypted with the DC's `.pvk`
/// private key, reversed, then RSA-decrypted — see impacket
/// `DPAPI_DOMAIN_RSA_MASTER_KEY` + `privatekeyblob_to_pkcs1`). It needs an RSA
/// implementation, which is out of scope here; this refuses loudly rather than
/// fabricating a key.
pub fn derive_master_key_from_domain_backup(
    _domain_key: &[u8],
    _pvk: &[u8],
) -> Result<[u8; MASTER_KEY_LEN], DpapiError> {
    Err(DpapiError::DomainBackupUnsupported)
}

/// Encode `s` as UTF-16LE bytes (no trailing NUL).
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Encode `s + "\0"` as UTF-16LE bytes (the SID form impacket HMACs over).
fn utf16le_with_nul(s: &str) -> Vec<u8> {
    let mut v = utf16le(s);
    v.extend_from_slice(&[0, 0]);
    v
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

    // ── Independent oracle ──────────────────────────────────────────────────
    // impacket 0.13.1 `tests/misc/test_dpapi.py::DPAPITests::systemMasterKeyFile`:
    // a real Windows master-key file (GUID ea95eba8-…) whose 64-byte master key
    // impacket recovers from the LSA `UserKey` pre-key and asserts against a
    // value extracted with secretsdump/mimikatz. Confirmed locally:
    //   $ python3 -c 'from impacket.dpapi import MasterKeyFile, MasterKey; ...'
    //   decrypted == systemMasterKey  -> True
    // HashAlgo=0x800e (SHA-512), CryptAlgo=0x6610 (AES-256-CBC), rounds=17400.
    const SYSTEM_MK_FILE: &str = "020000000000000000000000650061003900350065006200610038002d0062006100300030002d0034006500310061002d0062003400330066002d00350031006500610033003000310037003100640031003100000000000000000006000000b00000000000000090000000000000001400000000000000000000000000000002000000f42f61ea0c9647bf403819898452089ff84300000e80000010660000e2441dec11a6b6f03ffebba1e71473f78da46a52b12caff7df9925ed6ac89d84050ad15cfe88ec50ece201e5a80eb198909ff8c781510f78859b96cfade433c83a7f3fc19926b0280e6a196ef1b0b5e1b3c1ab426120da53f24e5989f8a7d3dde86ac444901401a6df6407f550d197ff27c91abb5c331250b5a7ce58c1f61fd0d656360df58e6f5b5faac639661aa89402000000bdc1f9592357353a2a3ebcf8cedc72bbf84300000e800000106600001231d67ec689fea9f6de6bd66a21e28d5405232df71deae5bf3ab63c6cb2cac08ad17456979d72b70de13afc2b61d05434161191dcdfb24aaac7ed0275f71eff9f936a559aff4be6301ba99d66bd8e07b1a325c73c7a4da97117f80551a3f0a75da9fcc37c4d2bb43b5a9ef1684446ae0300000000000000000000000000000000000000";
    const SYSTEM_USER_KEY: &str = "458dc597034d8801fc6fe3b342817caabb81a0cb";
    const SYSTEM_MASTER_KEY: &str = "682a9b8923ff4ca7ce0ef7e4cee061f0ff942cd31c7703ec60792740b2e7d0b1b5115d1ff77e10b77e189e0d6e99d5b668190ecd44fa84e82e049f406e2c2a59";

    #[test]
    fn parse_system_masterkey_file_header() {
        let f = parse_masterkey_file(&hex(SYSTEM_MK_FILE)).expect("parse file");
        assert_eq!(f.version, 2);
        assert_eq!(f.guid, "ea95eba8-ba00-4e1a-b43f-51ea30171d11");
        assert_eq!(f.flags, 0x6);
        assert_eq!(f.master_key.len(), 176);
        assert_eq!(f.backup_key.len(), 144);
        assert_eq!(f.cred_hist.len(), 20);
        assert_eq!(f.domain_key.len(), 0);
    }

    #[test]
    fn parse_system_master_key_subblob_fields() {
        let f = parse_masterkey_file(&hex(SYSTEM_MK_FILE)).expect("parse file");
        let mk = parse_master_key(&f.master_key).expect("parse mk");
        assert_eq!(mk.version, 2);
        assert_eq!(mk.rounds, 17400);
        assert_eq!(mk.alg_id_hash, 0x800e);
        assert_eq!(mk.alg_id_encrypt, 0x6610);
        assert_eq!(mk.salt.to_vec(), hex("f42f61ea0c9647bf403819898452089f"));
    }

    // Tier-2 (impacket-anchored): the derived 64-byte master key MUST equal the
    // value impacket's MasterKey.decrypt produces from the same pre-key.
    #[test]
    fn derive_system_master_key_matches_impacket() {
        let f = parse_masterkey_file(&hex(SYSTEM_MK_FILE)).expect("parse file");
        let mk = parse_master_key(&f.master_key).expect("parse mk");
        let pre_key = hex(SYSTEM_USER_KEY);
        let derived = derive_master_key_from_prekey(&mk, &pre_key).expect("derive");
        assert_eq!(derived.to_vec(), hex(SYSTEM_MASTER_KEY));
    }

    #[test]
    fn wrong_prekey_fails_hmac() {
        let f = parse_masterkey_file(&hex(SYSTEM_MK_FILE)).expect("parse file");
        let mk = parse_master_key(&f.master_key).expect("parse mk");
        let bad = [0xABu8; 20];
        assert!(matches!(
            derive_master_key_from_prekey(&mk, &bad),
            Err(DpapiError::HmacMismatch)
        ));
    }

    // impacket `deriveKeysFromUser(sid, password)` key1 (SHA-1 path), confirmed:
    //   sid="S-1-5-21-1455520393-2011455520393-2019809541-4133251990-500",
    //   password="Admin456" -> 742ab02b5f80ea5658ffecd49491f77e9b3c536a
    // and SHA1(UTF16LE("Admin456")) = 7ca54db25c28c72a5ec9a43b08bf75937c8b5fc6.
    const DERIVE_SID: &str = "S-1-5-21-1455520393-2011455520393-2019809541-4133251990-500";
    const DERIVE_PWD: &str = "Admin456";
    const DERIVE_PWD_SHA1: &str = "7ca54db25c28c72a5ec9a43b08bf75937c8b5fc6";
    const DERIVE_PREKEY: &str = "742ab02b5f80ea5658ffecd49491f77e9b3c536a";

    #[test]
    fn prekey_from_password_matches_impacket() {
        let k = prekey_from_password(DERIVE_SID, DERIVE_PWD).expect("derive prekey");
        assert_eq!(k.to_vec(), hex(DERIVE_PREKEY));
    }

    #[test]
    fn prekey_from_sha1_matches_impacket() {
        let mut sha1 = [0u8; 20];
        sha1.copy_from_slice(&hex(DERIVE_PWD_SHA1));
        let k = prekey_from_sha1(DERIVE_SID, &sha1).expect("derive prekey");
        assert_eq!(k.to_vec(), hex(DERIVE_PREKEY));
    }

    #[test]
    fn domain_backup_path_refuses() {
        assert!(matches!(
            derive_master_key_from_domain_backup(&[0u8; 16], &[0u8; 16]),
            Err(DpapiError::DomainBackupUnsupported)
        ));
    }
}
