# 6. The master key is the analyst's input; refuse-don't-fabricate on a locked store

Date: 2026-07-24
Status: Accepted

## Context

Recovering a DPAPI secret needs the user (or domain) master key. That key comes
from a source `dpapi-core` deliberately does not own end-to-end: an LSASS cache
in a memory image, a master-key file + the user password on disk, or a domain
RSA backup key. Some of those paths are implemented (password derivation), one is
not (RSA domain backup). The question is what the tool does when it cannot
produce the key.

The fleet Secure-by-Design and fail-loud disciplines
(`CLAUDE.core.md`) demand that a bootstrap/prerequisite failure surface as a
loud, explicit diagnostic naming the offending value — never absorbed into an
empty or fabricated result. For a credential tool the stakes are higher: a
guessed or placeholder secret is fabricated evidence. The step-2 plan states this
as a binding "Refuse-don't-fabricate boundary"
(`docs/plans/dpapi-step2.md`), and the CLI's first RED test
(`9079454`) was written to enforce it.

## Decision

1. **The master key is an input to the CLI**, supplied as hex
   (`MasterKeyArg::master_key_hex`, `forensic/src/lib.rs`); `dpapi4n6` never
   attempts to guess, crack, or brute-force it.
2. **A store present but not unlockable is reported, not decrypted.**
   `CliError::Locked { store, mk_guid }` carries the master-key GUID so the
   analyst can source the right key, and the CLI exits non-zero
   (`forensic/src/main.rs` → `ExitCode::FAILURE`). This is "show the unrecognized
   value": the diagnostic names *which* master key is missing, not just that
   decryption failed.
3. **Unimplemented key paths refuse loudly.**
   `masterkey::derive_master_key_from_domain_backup` returns
   `DpapiError::DomainBackupUnsupported` rather than fabricate a key — the RSA
   domain-backup path "needs an RSA implementation, which is out of scope here;
   this refuses loudly rather than fabricating a key" (`core/src/masterkey.rs`
   doc).

## Consequences

- The examiner can distinguish "store not present", "store present but locked
  (here is the GUID)", and "store decrypted" — three distinct, honest outcomes,
  never conflated into a clean-looking empty or a plausible wrong secret.
- The non-zero exit on a locked store makes the CLI scriptable without false
  positives: a pipeline sees failure, not a silent empty success.
- The RSA domain-backup path is a documented, typed gap rather than a hidden one;
  wiring it in later is an additive change (new master-key source), not a
  behavior reversal.
