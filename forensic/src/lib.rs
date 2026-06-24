//! `dpapi4n6` — forensic CLI over the [`dpapi_core`] decoders.
//!
//! The on-disk auditor for DPAPI-protected stores: Chrome/Edge (`Local State`
//! cookie key + `v10`/`v20` cookies), Credential Manager, Vault (`VPOL`/`VCRD`),
//! and Wi-Fi (`Wlansvc` PSK). Every secret is recovered through `dpapi_core` (all
//! crypto is audited RustCrypto), and the **master key is the analyst's input** —
//! when it is unavailable the CLI reports the store as *present but locked* with
//! the offending master-key GUID and a non-zero exit, never a guessed secret.
//!
//! Decision logic lives in this library (the testable `decode_*` functions +
//! [`Cli::run`]); `main.rs` is a thin shell (Humble Object).

pub use dpapi_core;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Serialize;

use dpapi_core::{
    decrypt_credential, decrypt_local_state_key, decrypt_v10_cookie, decrypt_vcrd_attribute,
    decrypt_vpol_keys, decrypt_wlan_key_material, detect_chrome_cookie_encoding,
    extract_key_material, parse_credential_file, parse_dpapi_blob, parse_internet_explorer,
    parse_local_state_encrypted_key, parse_vcrd_attributes, parse_vpol_file, ChromeCookieEncoding,
    DpapiError,
};

/// CLI error: a clear, typed failure surfaced to the user (never a guessed secret).
#[derive(Debug)]
pub enum CliError {
    /// An underlying `dpapi_core` decode/decrypt failure.
    Dpapi(DpapiError),
    /// A filesystem read failed (path + reason).
    Io(String),
    /// The master-key material was malformed (e.g. bad hex / wrong length).
    BadMasterKey(String),
    /// A store is present but cannot be unlocked with the supplied key material.
    /// Carries the master-key GUID so the analyst can source the right key.
    Locked { store: String, mk_guid: String },
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Dpapi(e) => write!(f, "decode failed: {e}"),
            CliError::Io(s) => write!(f, "io error: {s}"),
            CliError::BadMasterKey(s) => write!(f, "bad master key: {s}"),
            CliError::Locked { store, mk_guid } => write!(
                f,
                "{store} store present but LOCKED: no usable master key (master-key GUID {mk_guid}); supply the key for that GUID"
            ),
        }
    }
}

impl std::error::Error for CliError {}

impl From<DpapiError> for CliError {
    fn from(e: DpapiError) -> Self {
        CliError::Dpapi(e)
    }
}

/// A recovered secret from one store (the unit of CLI output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreResult {
    /// The store kind (`browser` / `credman` / `vault` / `wifi`).
    pub store: String,
    /// A human label for the recovered item (target / resource / "PSK" / "cookie").
    pub label: String,
    /// The recovered plaintext secret.
    pub secret: String,
    /// Optional account/username context.
    pub account: Option<String>,
}

/// The CLI's overall result: the recovered items across the requested stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliReport {
    pub results: Vec<StoreResult>,
}

/// `dpapi4n6` — recover DPAPI-protected secrets from acquired Windows artifacts.
#[derive(Debug, Parser)]
#[command(name = "dpapi4n6", version, about = "Forensic DPAPI store auditor")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    /// Emit the report as JSON instead of a human table.
    #[arg(long, global = true)]
    pub json: bool,
}

/// The master-key material, shared by every subcommand: the 64-byte user/SYSTEM
/// master key as hex (e.g. impacket's `-key 0x...` value, sans `0x`).
#[derive(Debug, clap::Args)]
pub struct MasterKeyArg {
    /// The 64-byte DPAPI master key, hex-encoded.
    #[arg(long = "master-key", value_name = "HEX")]
    pub master_key_hex: String,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Chrome/Edge: decrypt the `Local State` cookie key, then a `v10`/`v20` cookie.
    Browser {
        /// Path to the browser `Local State` JSON file.
        #[arg(long)]
        local_state: PathBuf,
        /// Path to a file holding one raw `encrypted_value` cookie blob (optional).
        #[arg(long)]
        cookie: Option<PathBuf>,
        #[command(flatten)]
        key: MasterKeyArg,
    },
    /// Credential Manager: decode a `Credentials\<hex>` file.
    Credman {
        /// Path to the Credential Manager file.
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        key: MasterKeyArg,
    },
    /// Vault: decrypt a `Policy.vpol` + one `<GUID>.vcrd` record.
    Vault {
        /// Path to the `Policy.vpol` file.
        #[arg(long)]
        vpol: PathBuf,
        /// Path to a `<GUID>.vcrd` record file.
        #[arg(long)]
        vcrd: PathBuf,
        #[command(flatten)]
        key: MasterKeyArg,
    },
    /// Wi-Fi: decode a `Wlansvc` profile XML's `<keyMaterial>` PSK.
    Wifi {
        /// Path to the WLAN profile XML.
        #[arg(long)]
        profile: PathBuf,
        #[command(flatten)]
        key: MasterKeyArg,
    },
}

/// Decode a 64-byte master key from hex, erroring loudly on bad input.
pub fn parse_master_key_hex(hex: &str) -> Result<Vec<u8>, CliError> {
    let s = hex.strip_prefix("0x").unwrap_or(hex);
    if s.len() % 2 != 0 {
        return Err(CliError::BadMasterKey(format!(
            "odd length ({} chars)",
            s.len()
        )));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, CliError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(CliError::BadMasterKey(format!("non-hex byte {other:#04x}"))),
    }
}

/// Map a master-key decode failure to a `Locked` report carrying the blob's
/// master-key GUID, so the analyst knows *which* key to source. Any other error
/// propagates as-is. Used by every store's decode path.
fn locked_or_err(store: &str, blob_bytes: &[u8], e: DpapiError) -> CliError {
    match e {
        DpapiError::HmacMismatch
        | DpapiError::DecryptionFailed
        | DpapiError::DomainBackupUnsupported => {
            let mk_guid = parse_dpapi_blob(blob_bytes).map_or_else(
                |_| "unknown".to_string(),
                |b| guid_to_string(&b.master_key_guid),
            );
            CliError::Locked {
                store: store.to_string(),
                mk_guid,
            }
        }
        other => CliError::Dpapi(other),
    }
}

/// Format a 16-byte GUID as the canonical mixed-endian string.
fn guid_to_string(g: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

// --- Decode helpers (no I/O; the testable core of each subcommand) ---

/// Decode the browser cookie key from `Local State` JSON, optionally decrypting a
/// `v10`/`v20` cookie blob.
///
/// Extracts `os_crypt.encrypted_key`, recovers the 32-byte AES cookie key via the
/// master key, and (when `cookie_blob` is given) AES-GCM-decrypts the `v10`/`v20`
/// value. A wrong/absent master key surfaces as a `Locked` result naming the
/// blob's master-key GUID — never a guessed cookie.
pub fn decode_browser(
    local_state_json: &str,
    cookie_blob: Option<&[u8]>,
    master_key: &[u8],
) -> Result<Vec<StoreResult>, CliError> {
    let value: serde_json::Value = serde_json::from_str(local_state_json)
        .map_err(|e| CliError::Io(format!("Local State is not valid JSON: {e}")))?;
    let encrypted_key_b64 = value
        .get("os_crypt")
        .and_then(|o| o.get("encrypted_key"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::Io("Local State has no os_crypt.encrypted_key".to_string()))?;

    let key_blob = parse_local_state_encrypted_key(encrypted_key_b64.as_bytes())?;
    let cookie_key = decrypt_local_state_key(&key_blob, master_key)
        .map_err(|e| locked_or_err("browser", &key_blob, e))?;

    let mut results = vec![StoreResult {
        store: "browser".to_string(),
        label: "cookie-key".to_string(),
        secret: hex_encode(&cookie_key),
        account: None,
    }];

    if let Some(blob) = cookie_blob {
        let plaintext = match detect_chrome_cookie_encoding(blob) {
            ChromeCookieEncoding::V10 { nonce, ciphertext }
            | ChromeCookieEncoding::V20 { nonce, ciphertext } => {
                decrypt_v10_cookie(&nonce, &ciphertext, &cookie_key)?
            }
            ChromeCookieEncoding::DpapiBlob(_) | ChromeCookieEncoding::Raw => {
                return Err(CliError::Io(
                    "cookie value is not a v10/v20 AES-GCM blob".to_string(),
                ))
            }
        };
        results.push(StoreResult {
            store: "browser".to_string(),
            label: "cookie".to_string(),
            secret: String::from_utf8_lossy(&plaintext).into_owned(),
            account: None,
        });
    }
    Ok(results)
}

/// Decode a Credential Manager file's blob.
pub fn decode_credman(file_bytes: &[u8], master_key: &[u8]) -> Result<Vec<StoreResult>, CliError> {
    let blob = parse_credential_file(file_bytes)?;
    let cred =
        decrypt_credential(&blob, master_key).map_err(|e| locked_or_err("credman", &blob, e))?;
    Ok(vec![StoreResult {
        store: "credman".to_string(),
        label: cred.target,
        secret: cred.secret,
        account: Some(cred.username),
    }])
}

/// Decode a Vault `VPOL` policy + one `VCRD` record into its web credentials.
pub fn decode_vault(
    vpol_bytes: &[u8],
    vcrd_bytes: &[u8],
    master_key: &[u8],
) -> Result<Vec<StoreResult>, CliError> {
    let vpol_blob = parse_vpol_file(vpol_bytes)?;
    let keys = decrypt_vpol_keys(&vpol_blob, master_key)
        .map_err(|e| locked_or_err("vault", &vpol_blob, e))?;

    let attrs = parse_vcrd_attributes(vcrd_bytes)?;
    let mut results = Vec::new();
    for attr in &attrs {
        // Only attributes carrying an encrypted payload yield a credential.
        let Ok(cleartext) = decrypt_vcrd_attribute(attr, &keys.key1) else {
            continue;
        };
        if let Ok(cred) = parse_internet_explorer(&cleartext) {
            results.push(StoreResult {
                store: "vault".to_string(),
                label: cred.resource,
                secret: cred.password,
                account: Some(cred.username),
            });
        }
    }
    Ok(results)
}

/// Decode a Wi-Fi profile XML's PSK.
pub fn decode_wifi(profile_xml: &str, master_key: &[u8]) -> Result<Vec<StoreResult>, CliError> {
    let key_material = extract_key_material(profile_xml)
        .ok_or_else(|| CliError::Io("profile XML has no <keyMaterial>".to_string()))?;
    // Resolve the blob bytes so a locked store can still name its master-key GUID.
    let blob = hex_decode(key_material)?;
    let psk = decrypt_wlan_key_material(key_material, master_key)
        .map_err(|e| locked_or_err("wifi", &blob, e))?;
    Ok(vec![StoreResult {
        store: "wifi".to_string(),
        label: "PSK".to_string(),
        secret: psk,
        account: None,
    }])
}

impl Cli {
    /// Execute the parsed CLI, reading the artifact files and dispatching to the
    /// store decoder. Returns the recovered report or a typed [`CliError`].
    pub fn run(&self) -> Result<CliReport, CliError> {
        let results = match &self.command {
            Command::Browser {
                local_state,
                cookie,
                key,
            } => {
                let mk = parse_master_key_hex(&key.master_key_hex)?;
                let json = read_to_string(local_state)?;
                let cookie_bytes = match cookie {
                    Some(p) => Some(read_bytes(p)?),
                    None => None,
                };
                decode_browser(&json, cookie_bytes.as_deref(), &mk)?
            }
            Command::Credman { file, key } => {
                let mk = parse_master_key_hex(&key.master_key_hex)?;
                decode_credman(&read_bytes(file)?, &mk)?
            }
            Command::Vault { vpol, vcrd, key } => {
                let mk = parse_master_key_hex(&key.master_key_hex)?;
                decode_vault(&read_bytes(vpol)?, &read_bytes(vcrd)?, &mk)?
            }
            Command::Wifi { profile, key } => {
                let mk = parse_master_key_hex(&key.master_key_hex)?;
                decode_wifi(&read_to_string(profile)?, &mk)?
            }
        };
        Ok(CliReport { results })
    }
}

/// Read a file to a `String`, mapping I/O failure to a [`CliError::Io`].
fn read_to_string(path: &std::path::Path) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(|e| CliError::Io(format!("{}: {e}", path.display())))
}

/// Read a file to bytes, mapping I/O failure to a [`CliError::Io`].
fn read_bytes(path: &std::path::Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::Io(format!("{}: {e}", path.display())))
}

/// Hex-encode bytes (lowercase) for displaying a recovered raw key.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode an ASCII hex string into bytes, erroring loudly on bad input.
fn hex_decode(s: &str) -> Result<Vec<u8>, CliError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(CliError::BadMasterKey(format!(
            "odd-length hex ({} chars)",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push((nibble(bytes[i])? << 4) | nibble(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

/// Render a [`CliReport`] as a human-readable table.
pub fn render_text(report: &CliReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if report.results.is_empty() {
        return "No secrets recovered.\n".to_string();
    }
    for r in &report.results {
        let account = r.account.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "[{}] {} | account={} | secret={}",
            r.store, r.label, account, r.secret
        );
    }
    out
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

    // Reuse the impacket-validated tier-1 master key + vectors from dpapi-core.
    const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";

    // Browser: Local State encrypted_key (base64) + a v10 cookie (impacket vector).
    const ENCRYPTED_KEY_B64: &str = "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAAz8Z9e40C+SoouK05ivQzGAAAAAAIAAAAAABBmAAAAAQAAIAAAAAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/AAAAAA6AAAAAAgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAA+t/5261X1EPXoNd8+fv91ognzpGyym/1M78vdGfOMphl2Zzre4QfJx4U0fUIzjosQAAAAP5yd3Yln699MQCEn7TqSfxp/Ba+vR7Ji1pSJ7TPr7zimD/5Slev0vK6H5r6Mq46ohSMEPLzAWzKvD5xxvJt1sA=";
    const V10_COOKIE_HEX: &str = "7631300102030405060708090a0b0c1b5af334ffe7a1fe676c5ab453c8848232ab94aa630c69bae71883958ba23e4dfe4cc5faff526ce54b";
    const V10_PLAINTEXT: &str = "forensic-session-token-42";

    // Credential Manager (impacket vector): on-disk CredentialFile.
    const CRED_FILE_HEX: &str = "01000000b60100000000000001000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc600000000020000000000106600000001000020000000aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899000000000e800000000200004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000e2d6d8670704ca1daecd786fe94c133a68fd50708f3ed0ca7013b5e0bc5f61296b5a32b935d6b5404a2162bc26cf561cb7b45f58c7cc8d18305c9dd068860bd4f6cea89ea34db4acde8ebae4606ec1261e8006b104d96eb42975e0df1042aa1161e6c70af5530507238141080d7d7ea1f16a9609963b296143504a4af284826e1436641c74c6dc00d0b1731794887426fc4e4f4d440416c1874aaf34b6a74411d9ed966d73b6a8d05c8546329e7bb4222d2518ab8e2e7d8c47624ec64ecc8a0040000000e0585a675fef9ed63f72673bd9408684dc7fc86ad4926a76c432af933aeab68447e56860b1715cff46516cf38433a856b28a5d0653313a11664b98f2361e8cca";
    const CRED_EXPECT_TARGET: &str = "Domain:target=TERMSRV/fileserver01";
    const CRED_EXPECT_SECRET: &str = "S3cr3t-P@ssw0rd!";

    // Wi-Fi (impacket vector): keyMaterial hex + PSK.
    const WIFI_KEY_MATERIAL_HEX: &str = "01000000D08C9DDF0115D1118C7A00C04FC297EB0100000033F19F5EE340BE4A8A2E2B4E62BD0CC600000000020000000000106600000001000020000000DEADBEEFCAFEBABE0011223344556677DEADBEEFCAFEBABE0011223344556677000000000E8000000002000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000051E2C9E20723EF48230A95FCEBBA31AF8BC567EDABBBD958F6E42E4CCE9236C240000000538815E34921B886D09A9CEAD4024E596A73C9C3B53E37A4481D05D7097751049323C613F78C8BD0D8A3AAAB8BF9FBC966E87526245734D0C781DFE0214B1D70";
    const WIFI_EXPECT_PSK: &str = "CorrectHorseBatteryStaple";

    fn local_state_json() -> String {
        format!("{{\"os_crypt\":{{\"encrypted_key\":\"{ENCRYPTED_KEY_B64}\"}}}}")
    }

    fn wifi_xml() -> String {
        format!("<WLANProfile><MSM><security><sharedKey><keyMaterial>{WIFI_KEY_MATERIAL_HEX}</keyMaterial></sharedKey></security></MSM></WLANProfile>")
    }

    // --- arg parsing (always testable) ---

    #[test]
    fn cli_parses_browser_subcommand() {
        let cli = Cli::try_parse_from([
            "dpapi4n6",
            "browser",
            "--local-state",
            "/tmp/Local State",
            "--master-key",
            MASTER_KEY_HEX,
        ])
        .expect("parse");
        assert!(matches!(cli.command, Command::Browser { .. }));
    }

    #[test]
    fn cli_version_flag_supported() {
        // --version exits 0; try_parse_from surfaces it as a DisplayVersion error.
        let err = Cli::try_parse_from(["dpapi4n6", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn master_key_hex_parses_and_rejects_bad() {
        assert_eq!(parse_master_key_hex("0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(parse_master_key_hex("0x0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert!(parse_master_key_hex("0a0").is_err()); // odd
        assert!(parse_master_key_hex("zz").is_err()); // non-hex
    }

    // --- smoke: each store decodes the impacket vector through the CLI surface ---

    #[test]
    fn browser_decodes_cookie_to_plaintext() {
        let mk = hex(MASTER_KEY_HEX);
        let results =
            decode_browser(&local_state_json(), Some(&hex(V10_COOKIE_HEX)), &mk).expect("ok");
        assert!(results.iter().any(|r| r.secret == V10_PLAINTEXT));
    }

    #[test]
    fn credman_decodes_target_and_secret() {
        let mk = hex(MASTER_KEY_HEX);
        let results = decode_credman(&hex(CRED_FILE_HEX), &mk).expect("ok");
        let r = &results[0];
        assert_eq!(r.label, CRED_EXPECT_TARGET);
        assert_eq!(r.secret, CRED_EXPECT_SECRET);
    }

    #[test]
    fn wifi_decodes_psk() {
        let mk = hex(MASTER_KEY_HEX);
        let results = decode_wifi(&wifi_xml(), &mk).expect("ok");
        assert_eq!(results[0].secret, WIFI_EXPECT_PSK);
    }

    // --- refuse-don't-fabricate at the CLI boundary ---

    #[test]
    fn locked_store_reports_guid_not_a_secret() {
        let bad_mk = [0u8; 64];
        let err = decode_wifi(&wifi_xml(), &bad_mk).unwrap_err();
        match err {
            CliError::Locked { store, mk_guid } => {
                assert_eq!(store, "wifi");
                assert!(mk_guid.contains('-'), "GUID surfaced: {mk_guid}");
            }
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[test]
    fn json_report_serializes() {
        let report = CliReport {
            results: vec![StoreResult {
                store: "wifi".into(),
                label: "PSK".into(),
                secret: WIFI_EXPECT_PSK.into(),
                account: None,
            }],
        };
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains(WIFI_EXPECT_PSK));
    }
}
