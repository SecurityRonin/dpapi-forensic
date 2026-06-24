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

## DPAPI blob decrypt vectors (step-1)

The `core/src/decrypt.rs` tier-1 vectors (`MASTER_KEY_HEX`, `VECTOR1_BLOB_HEX`,
`VECTOR2_BLOB_HEX`) are inline in that test module; provenance recorded in their
source comments (blob minted on Windows, key via mimikatz, plaintext confirmed by
impacket `DPAPI_BLOB.decrypt`).
