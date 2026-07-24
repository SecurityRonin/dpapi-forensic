# dpapi-forensic — Product Requirements

*Reverse-written from a same-session read of the repo (`README.md`, both
`Cargo.toml`s, `core/src/*.rs`, `forensic/src/lib.rs` + `main.rs`, and the git
history through `d019def`, 2026-07-24). Every current-state claim below is
grounded in that read; the load-bearing decisions live as ADRs
[0001](decisions/0001-core-forensic-split.md)–[0008](decisions/0008-crate-naming-and-msrv.md)
under [`docs/decisions/`](decisions/). The step-2 build plan that shaped the
auditor is [`docs/plans/dpapi-step2.md`](plans/dpapi-step2.md).*

## Executive Summary

`dpapi-forensic` recovers Windows secrets protected by the **Data Protection
API (DPAPI)** from acquired evidence — no live target, no admin agent, no I/O
beyond reading the artifact files an analyst already extracted. It ships two
things: `dpapi-core`, a pure-`&[u8]` library that parses the `DPAPI_BLOB` wire
format and decrypts it **given a master key** (AES-256-CBC / 3DES-CBC blobs,
AES-256-GCM Chrome/Edge `v10`/`v20` cookies), and `dpapi4n6`, the CLI an examiner
runs against on-disk stores: Chrome/Edge (`Local State` cookie key + cookies),
Credential Manager, Vault (`VPOL`/`VCRD`), and Wi-Fi (`Wlansvc` PSK).

The design turns on one fact: **the blob format and the decrypt-given-key crypto
are byte-identical on disk and in live memory** — only the *source* of the master
key differs by medium (an LSASS cache in a memory image vs. a master-key file
plus password derivation on disk). So the crypto is a medium-agnostic library
that both a memory tool and a disk tool link, and the master key is the analyst's
**input**. When it is unavailable, `dpapi4n6` reports the store as *present but
locked* — naming the offending master-key GUID and exiting non-zero — and never
guesses. All cryptography is audited RustCrypto; the tool refuses (typed error)
rather than fabricate plausible-but-wrong plaintext, because in a forensic tool
fabricated plaintext is fabricated evidence.

## 1. Problem

DPAPI is one of the largest Windows credential-protection surfaces: browser
saved passwords and cookie keys, Credential Manager, Vault, Wi-Fi PSKs, and the
master-key files themselves. Existing recovery tooling (impacket, mimikatz,
DPAPImk) is either Python (slow, dependency-heavy, hard to embed) or live-only
(needs the running target). A DFIR examiner working from an acquired disk or a
memory image wants a **single static binary** that decodes these stores offline,
given key material they already recovered, and that is honest when a store cannot
be unlocked — not a tool that emits a plausible-looking wrong secret.

The crypto is also duplicated across the fleet: `memory-forensic`'s `memf-windows`
already carried a DPAPI blob decoder for the LSASS-cache path. Re-implementing
the identical blob/crypto for a disk tool would fork it.

## 2. Users

- **DFIR analysts / incident responders** — recover browser cookies and saved
  credentials, Vault web credentials, and Wi-Fi keys from an acquired image to
  reconstruct account access and lateral movement.
- **Malware / intrusion analysts** — decrypt credentials an adversary would have
  targeted, given a master key derived from the user password or a domain backup.
- **Fleet tools (library consumers)** — `memory-forensic` (LSASS-cache master
  keys), a future disk orchestrator (master-key files), and `issen` link
  `dpapi-core` for the shared blob/crypto rather than re-deriving it.

## 3. What it does

`dpapi-core` (library, byte-oriented, no I/O):

- **`parse_dpapi_blob(&[u8])`** — decode the `DPAPI_BLOB` wire format: version,
  master-key GUID, description, hash/cipher algorithm IDs, salt, HMAC key,
  ciphertext, and trailing integrity HMAC (field names mirror impacket).
- **`decrypt_dpapi_blob(blob, master_key)`** — derive the session key
  (HMAC-SHA1/SHA512) and decrypt AES-256-CBC or 3DES-CBC, verifying the integrity
  HMAC.
- **`chrome`** — classify a Chrome/Edge `encrypted_value`
  (`v10`/`v20`/classic-DPAPI/raw) and unwrap the AES-256-GCM variants; decode the
  `Local State` `os_crypt.encrypted_key` (base64 → DPAPI blob → 32-byte AES key).
- **`masterkey`** — parse a master-key file
  (`%APPDATA%\Microsoft\Protect\<SID>\<GUID>`) and derive the user master key
  from the password (SHA1/PBKDF2-HMAC prekey), impacket-anchored.
- **`credential` / `vault` / `wifi`** — Credential Manager `CREDENTIAL_BLOB`,
  Vault `VPOL`/`VCRD` web credentials, and `Wlansvc` `keyMaterial` PSK decoders.

`dpapi4n6` (CLI, thin Humble-Object shell over the library):

- Subcommands `browser`, `credman`, `vault`, `wifi`, each taking artifact paths
  plus a hex master key; `--json` for machine output, text otherwise.
- A store present but not unlockable surfaces as a typed `Locked { store,
  mk_guid }` with a non-zero exit — never a guessed secret.

## 4. Scope (in)

- Offline decode/decrypt of DPAPI blobs and the four store families above from
  files the analyst supplies.
- User master-key derivation from a master-key file + password.
- The `dpapi4n6` CLI as the analyst-facing surface.

## 5. Non-goals (out)

- **No acquisition and no live target.** The tool reads files; it does not attach
  to LSASS, mount images, or walk a filesystem tree (an orchestrator or `4n6mount`
  supplies the paths).
- **No key guessing / brute force.** The master key is an input; the tool never
  attempts to crack it.
- **No RSA domain-backup-key path (yet).** `derive_master_key_from_domain_backup`
  refuses with `DpapiError::DomainBackupUnsupported` rather than fabricate — it
  needs an RSA implementation that is out of current scope (ADR
  [0006](decisions/0006-master-key-input-refuse-boundary.md)).
- **No hand-rolled crypto.** Every primitive is a RustCrypto crate (ADR
  [0003](decisions/0003-audited-crypto-no-fabrication.md)).

## 6. Artifact family

| Store | On-disk artifact | Decoder |
|---|---|---|
| Chrome/Edge cookie key | `Local State` (`os_crypt.encrypted_key`) | `chrome` |
| Chrome/Edge cookies | `encrypted_value` (`v10`/`v20`) | `chrome` |
| User master key | `Protect\<SID>\<GUID>` master-key file | `masterkey` |
| Credential Manager | `Credentials\<hex>` file | `credential` |
| Vault | `Policy.vpol` + `<GUID>.vcrd` | `vault` |
| Wi-Fi | `Wlansvc` profile XML `<keyMaterial>` | `wifi` |

## 7. Validation approach

Correctness is proven against an **independent third-party oracle** —
**impacket 0.13.1** (`impacket/dpapi.py`) — not only self-authored fixtures (ADR
[0007](decisions/0007-impacket-oracle-validation.md)). The git history shows the
blob, master-key, browser, credential, vault, and Wi-Fi decoders each landing as
a RED test pinned to an impacket-minted vector, then a GREEN implementation
("matches impacket" / "impacket-anchored"). The library is `forbid(unsafe)` with
`unwrap_used`/`expect_used` denied (ADR
[0005](decisions/0005-unsafe-forbid-panic-free.md)): a bad key, IV length, or
HMAC is a typed `DpapiError`, never a panic or a fabricated plaintext.

---

[Privacy Policy](https://securityronin.github.io/dpapi-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/dpapi-forensic/terms/) · © 2026 Security Ronin Ltd
