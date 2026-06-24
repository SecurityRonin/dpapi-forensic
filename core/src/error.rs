//! Error type shared across the DPAPI blob parser, decryptor, and Chrome cookie
//! unwrapper.

#[derive(Debug, thiserror::Error)]
pub enum DpapiError {
    #[error("data too short: need at least {needed} bytes, got {got}")]
    TooShort { needed: usize, got: usize },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("not a DPAPI blob: provider GUID {0} != the DPAPI provider")]
    NotDpapiProvider(String),
    #[error("unsupported algorithm ID: {0:#010x}")]
    UnsupportedAlgId(u32),
    #[error("invalid key or IV length")]
    InvalidKeyLength,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("HMAC verification failed")]
    HmacMismatch,
    #[error("UTF-16 decode error")]
    Utf16Error,
    #[error("domain RSA backup-key path is not implemented")]
    DomainBackupUnsupported,
    #[error("base64 decode error in Local State encrypted_key")]
    Base64Error,
    #[error("Local State encrypted_key missing the 5-byte 'DPAPI' prefix (first bytes: {0})")]
    MissingDpapiPrefix(String),
    #[error("recovered cookie key has unexpected length: expected {expected} bytes, got {got}")]
    UnexpectedKeyLength { expected: usize, got: usize },
}
