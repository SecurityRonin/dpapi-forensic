# dpapi step-2 — on-disk auditor + `dpapi4n6` CLI (TDD plan)

## Scope

Step 1 shipped `dpapi-core`: parse `DPAPI_BLOB`, decrypt **given a master key**,
unwrap Chrome/Edge `v10`/`v20` AES-256-GCM cookies, and (merged) derive a user
master key from a master-key file (`masterkey.rs`, impacket-anchored).

Step 2 builds the **on-disk auditor** on top of that merged `masterkey`: enumerate
DPAPI-protected stores on an acquired filesystem, decrypt them through `dpapi-core`,
and emit graded `forensicnomicon::report::Finding`s; plus the `dpapi4n6` CLI.

Impacket 0.13.1 (`impacket/dpapi.py`) is the independent oracle. Where a path is
not implemented (RSA domain-backup-key decryption), the code **refuses with a typed
error** — it never fabricates plaintext (this is a forensic tool; fabricated
plaintext is fabricated evidence).

## Layering — where each piece lives

`dpapi-core` is medium-agnostic (`&[u8]` in, no I/O, no findings). The existing
`chrome.rs` cookie unwrap already lives there. So:

- **Pure byte/crypto decoders → `dpapi-core`.** The browser cookie-key decode
  (`Local State` `encrypted_key` → 32-byte AES key) is a pure-bytes transform over
  the *already-decrypted master key* + a DPAPI blob; it belongs next to `chrome.rs`.
- **Enumeration + grading + I/O → `dpapi-forensic`.** Walking an acquired profile
  tree, reading files, picking master-key files by GUID, and emitting `Finding`s is
  the auditor's job. `dpapi-forensic` gains a `forensicnomicon` dependency for the
  report model.
- **CLI → `dpapi4n6` binary** in `dpapi-forensic` (`*4n6` fleet convention).

## Master-key layering (the spine every store reuses)

Every store decrypts the same way; only the *blob source* differs:

```
master-key file (%APPDATA%\Microsoft\Protect\<SID>\<GUID>)
  + user password / SHA1 pre-key            masterkey::derive_master_key_from_password
        │                                    (impacket MasterKey.decrypt — merged, step-1)
        ▼
  64-byte master key  ──────────────►  decrypt::decrypt_dpapi_blob(blob, mk, entropy?)
        ▲                                    (impacket DPAPI_BLOB.decrypt — merged, step-1)
        │
  (NOT implemented) RSA domain-backup  masterkey::derive_master_key_from_domain_backup
        key → DpapiError::DomainBackupUnsupported  (refuse, never fabricate)
```

The auditor selects the master-key file whose GUID matches `blob.guid_master_key`
(exposed on `DpapiBlob`), derives the master key once per GUID, caches it, and
feeds every blob protected by that key.

## On-disk auditor API (target shape — NOT all RED'd in this pass)

Each store decoder is a typed reader producing decoded records; the auditor grades
them into `Finding`s. Decoders that are pure-bytes live in `dpapi-core`; enumeration
lives in `dpapi-forensic`.

### 1. Browser (Chrome/Edge) — FIRST bounded deliverable (RED in this pass)

`dpapi-core`:

- `parse_local_state_encrypted_key(local_state_json_value: &[u8]) -> Result<Vec<u8>>`
  — accept the base64 `os_crypt.encrypted_key` *string bytes*; base64-decode; require
  and strip the 5-byte `DPAPI` prefix; return the inner DPAPI blob bytes. (JSON
  field extraction is the caller's job; this takes the already-located base64 value.)
- `decrypt_local_state_key(blob_bytes: &[u8], master_key: &[u8]) -> Result<[u8; 32]>`
  — parse the blob, `decrypt_dpapi_blob` with the master key (no entropy), require the
  plaintext to be exactly 32 bytes (the AES-256 cookie key), return it. A wrong/missing
  master key fails the blob's Sign-HMAC → `DpapiError`; never returns garbage.
- Cookie decryption then reuses the existing
  `detect_chrome_cookie_encoding` + `decrypt_v10_cookie` (already shipped).

`dpapi-forensic` (later in step-2, not this RED): a `browser` auditor that reads
`Local State` (JSON), extracts `os_crypt.encrypted_key`, decrypts the key, then walks
the `Cookies` / `Login Data` SQLite DBs and decrypts each `encrypted_value` /
`password_value`, emitting one `Finding` per recovered secret (Category `Residue`,
graded `Medium`/`High` — a recovered credential is high-value residue), and a refuse
`Finding` (Severity `None`/unrated, with the offending GUID + path) when the master
key is unavailable.

### 2. Credential Manager (later)

`%APPDATA%\Microsoft\Credentials\*` — each file is a `CredentialFile` wrapping a
DPAPI blob (impacket `CredentialFile` / `CREDENTIAL_BLOB`). Decode → blob →
`decrypt_dpapi_blob` → `CREDENTIAL_BLOB` fields (target, username, unknown/secret).

### 3. Vault (later)

`%APPDATA%\Microsoft\Vault\` + `%LOCALAPPDATA%\Microsoft\Vault\` — `VAULT_VPOL` /
`VAULT_VPOL_KEYS` (two AES keys unwrapped via DPAPI) then `VAULT_VCRD` attributes
decrypted with those keys (impacket `VAULT_*`, `Policy.vpol`).

### 4. Wi-Fi keys (later)

`Wlansvc` profile XML — the `<keyMaterial>` hex is a SYSTEM-DPAPI blob; decode → blob
→ `decrypt_dpapi_blob` with the SYSTEM master key.

## `dpapi4n6` CLI surface (later in step-2)

Persona: a DFIR analyst with an acquired (mounted/extracted) Windows profile and a
known/derivable user password. Common path = fewest decisions:

```
dpapi4n6 browser   --profile <dir> --sid <S-1-5-…> --password <pw>   [--json]
dpapi4n6 credman   --profile <dir> --sid <S-1-5-…> --password <pw>   [--json]
dpapi4n6 vault     --profile <dir> --sid <S-1-5-…> --password <pw>   [--json]
dpapi4n6 wifi      --system-hive <dir>  --system-key <…>             [--json]
dpapi4n6 audit     --profile <dir> --sid … --password …             [--json]   # all stores
```

- `--password` / `--sha1` are alternatives (one pre-key source); grouped as one choice.
- Master-key files are auto-located under `<profile>/AppData/Roaming/Microsoft/Protect/<sid>/`.
- Default output is a human findings table; `--json` emits the `forensicnomicon`
  report model (sanitized via `jsonguard` for attacker-controlled strings — cookie
  hosts, credential targets).
- `--version` prints `dpapi4n6 X.Y.Z`, exit 0 (fleet release-gate requirement).

## Refuse-don't-fabricate boundary (binding)

- **RSA domain-backup key path is NOT implemented.**
  `masterkey::derive_master_key_from_domain_backup` already returns
  `DpapiError::DomainBackupUnsupported`. The auditor must surface this as a typed
  refusal (and, in the report model, an unrated `Finding` naming the master-key GUID +
  file path), **never** a fabricated/placeholder master key or plaintext.
- **No usable master key ⇒ no plaintext.** When the password is wrong (Sign-HMAC
  mismatch) or no master-key file matches the blob's GUID, the decode returns
  `DpapiError`; the auditor records that the store is *present but locked*, with the
  offending GUID — it never emits a guessed/zeroed secret.
- All crypto stays on audited RustCrypto crates (`aes`, `aes-gcm`, `cbc`, `des`,
  `hmac`, `sha1`, `sha2`); no hand-rolled primitives.

## Oracle vectors (impacket 0.13.1, host-validated)

The browser-path RED test pins against a vector minted through impacket itself
(provenance + reproduction in `tests/data/README.md` and `docs/corpus-catalog.md`):

- **Master key** = the existing tier-1 impacket-validated key from `core/src/decrypt.rs`
  (`9828d987…81b0ce3`, recovered via mimikatz, plaintext confirmed by
  `impacket.dpapi.DPAPI_BLOB.decrypt`).
- **`Local State` `encrypted_key` blob** = a DPAPI blob (CALG_SHA_512 / AES-256-CBC,
  no entropy) minted by reproducing `DPAPI_BLOB.decrypt`'s inverse and **confirmed by
  impacket `DPAPI_BLOB(blob).decrypt(mk)` returning the 32-byte key**
  `2021…3e3f` (`bytes(range(0x20,0x40))`).
- **`v10` cookie** = `b"v10" + nonce(12) + AES-256-GCM(cookie_key, nonce, "forensic-session-token-42")`,
  produced with the same 32-byte key (Python `cryptography` AESGCM, which RustCrypto
  `aes-gcm` matches bit-for-bit).

Reproduction script: `tests/data/build_localstate_vector.py` (committed).

## TDD sequencing

1. **(this pass, RED)** `dpapi-core` browser cookie-key path:
   `parse_local_state_encrypted_key` + `decrypt_local_state_key`, with stubs returning
   typed errors so tests compile and FAIL. Tests pin the impacket key + the v10
   plaintext, and assert the refuse path errors when no usable master key is given.
2. GREEN: implement the two functions (base64 strip + blob decrypt + 32-byte check).
3. RED→GREEN: `dpapi-forensic` `forensicnomicon` dep + browser auditor emitting
   graded `Finding`s over a profile dir (I/O), with the locked-store refusal Finding.
4. RED→GREEN: Credential Manager, Vault, Wi-Fi decoders (each impacket-anchored).
5. RED→GREEN: `dpapi4n6` CLI (clap), `--version`, `--json` report output.
6. README rewrite + `docs/validation.md` (impacket differential) + corpus catalog.

Each step is two commits (RED failing tests, then GREEN), per fleet TDD discipline.
