# dpapi-forensic test data

Provenance for every fixture consumed by the test suite. Cross-references the
fleet catalog at `issen/docs/corpus-catalog.md` (machine index) — this file is the
co-located human-facing detail. Use straight ASCII in paths/commands.

## Browser cookie-key path (step-2, first bounded deliverable)

The browser RED test (`core/src/chrome.rs`) pins decoded values against a vector
minted **through impacket 0.13.1** (`impacket.dpapi.DPAPI_BLOB`), the documented
oracle. Classification: `SYNTHETIC` (minted), but the ground truth is established by
an **independent oracle** (impacket decrypt) rather than by us alone — tier-2 in the
fleet evidence taxonomy. The inline hex constants in the test are the committed copy;
the generator below reproduces them.

#### build_localstate_vector.py

- **Generator** (verbatim, committed): `tests/data/build_localstate_vector.py`
- **Run**: `python3 tests/data/build_localstate_vector.py` (needs `impacket==0.13.1`
  and `cryptography`; validated with anaconda Python 3.12 + impacket 0.13.1).
- **MD5**: `1dacd9375c15ab3c68487bff0028ccdd`
- **What it produces / pins**:
  - **Master key** `9828d987...81b0ce3` — the existing tier-1 impacket-validated DPAPI
    master key already in `core/src/decrypt.rs` (minted on Windows, key recovered with
    mimikatz, plaintext confirmed by `impacket.dpapi.DPAPI_BLOB.decrypt`, impacket 0.12.0).
  - **`Local State` `encrypted_key` DPAPI blob** (CALG_SHA_512 / AES-256-CBC, no
    entropy) — minted by reproducing the inverse of `DPAPI_BLOB.decrypt`, then
    **confirmed by impacket**: `DPAPI_BLOB(blob).decrypt(master_key)` returns the
    32-byte AES cookie key `2021...3e3f` (= `bytes(range(0x20, 0x40))`). As stored in
    Chrome/Edge `Local State`, this is `base64("DPAPI" + blob_bytes)`.
  - **`v10` cookie** `encrypted_value` — `b"v10" + nonce(12) +
    AES-256-GCM(cookie_key, nonce, b"forensic-session-token-42")`, produced with the
    same 32-byte key via Python `cryptography` AESGCM (bit-for-bit compatible with
    RustCrypto `aes-gcm`). Expected plaintext: `forensic-session-token-42`.

## Vault path (step-2, deliverable 3)

The Vault RED/GREEN test (`core/src/vault.rs`) pins decoded attributes against a
vector minted **through impacket 0.13.1** (`impacket.dpapi.VAULT_VPOL`,
`VAULT_VPOL_KEYS`, `VAULT_VCRD`, `VAULT_INTERNET_EXPLORER`, plus the `VAULT` action
flow in `impacket/examples/dpapi.py`). Classification: `SYNTHETIC` (minted), ground
truth established by an **independent oracle** (impacket parses the VPOL keys and
AES-CBC-decrypts the VCRD attribute back to the same web-credential fields) — tier-2.

#### build_vault_vector.py

- **Generator** (verbatim, committed): `tests/data/build_vault_vector.py`
- **Run**: `python3 tests/data/build_vault_vector.py` (needs `impacket==0.13.1`
  and `pycryptodome`; validated with anaconda Python 3.12 + impacket 0.13.1).
- **MD5**: `4f6250bd83b7a25b7ac8a477978e7ba0`
- **Two-stage chain pinned**:
  - **Policy** — `VPOL_FILE_HEX` is an impacket `VAULT_VPOL` wrapping an inner DPAPI
    blob (`VPOL_BLOB_HEX`, CALG_SHA_512 / AES-256, no entropy). impacket
    `VAULT_VPOL.Blob.decrypt(master_key)` yields `VAULT_VPOL_KEYS`, from which
    `Key1.bKeyBlob.bKey` / `Key2...` are the two 32-byte AES keys
    (`VPOL_KEY1_HEX` / `VPOL_KEY2_HEX`). The script asserts this round-trip.
  - **Record** — `VCRD_FILE_HEX` is an impacket `VAULT_VCRD` with one attribute
    (IV `ATTR_IV_HEX`). AES-CBC-decrypting `attribute['Data']` with `Key1` (impacket's
    `VAULT` example flow) yields a `VAULT_INTERNET_EXPLORER` cleartext that impacket
    decodes to Username `alice@example.com`, Resource `https://portal.example.com`,
    Password `V@ultP4ss!`. The script prints these from `VAULT_INTERNET_EXPLORER`, so
    the expected strings are genuinely impacket output, not self-authored.
  - Master key — the same tier-1 impacket-validated key (`9828d987...81b0ce3`).

## Credential Manager path (step-2, deliverable 2)

The Credential Manager RED/GREEN test (`core/src/credential.rs`) pins decoded fields
against a vector minted **through impacket 0.13.1** (`impacket.dpapi.CredentialFile`,
`DPAPI_BLOB`, `CREDENTIAL_BLOB`). Classification: `SYNTHETIC` (minted), ground truth
established by an **independent oracle** (impacket parses + decrypts back to the same
fields) — tier-2. Inline hex constants in the test are the committed copy.

#### build_credential_vector.py

- **Generator** (verbatim, committed): `tests/data/build_credential_vector.py`
- **Run**: `python3 tests/data/build_credential_vector.py` (needs `impacket==0.13.1`
  and `pycryptodome`; validated with anaconda Python 3.12 + impacket 0.13.1).
- **MD5**: `b4822d8516a52df9ef090174dd060bd8`
- **What it produces / pins**:
  - **Master key** — the same tier-1 impacket-validated key (`9828d987...81b0ce3`).
  - **On-disk `CredentialFile`** (`CRED_FILE_HEX`) — impacket `CredentialFile`
    wrapper (`Version(4)`, `Size(4)`, `Unknown(4)`) around the inner DPAPI blob
    (`CRED_BLOB_HEX`, CALG_SHA_512 / AES-256-CBC, no entropy). The inner blob is
    minted by reproducing the inverse of `DPAPI_BLOB.decrypt`.
  - **Confirmed by impacket**: `DPAPI_BLOB(CredentialFile(file)['Data']).decrypt(mk)`
    yields the cleartext, and `CREDENTIAL_BLOB(cleartext)` decodes to
    `Target="Domain:target=TERMSRV/fileserver01"`, `Username="CORP\\jdoe"`,
    secret (`Unknown` field) `"S3cr3t-P@ssw0rd!"`. The script asserts these
    round-trips, so the expected strings are genuinely impacket output, not
    self-authored.

## DPAPI blob decrypt vectors (step-1)

The `core/src/decrypt.rs` tier-1 vectors (`MASTER_KEY_HEX`, `VECTOR1_BLOB_HEX`,
`VECTOR2_BLOB_HEX`) are inline in that test module; provenance recorded in their
source comments (blob minted on Windows, key via mimikatz, plaintext confirmed by
impacket `DPAPI_BLOB.decrypt`).
