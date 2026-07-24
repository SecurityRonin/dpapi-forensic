# 7. Validate every decoder against impacket 0.13.1 as the independent oracle

Date: 2026-07-24
Status: Accepted

## Context

The fleet Doer-Checker / Evidence-Based-Rigor disciplines
(`CLAUDE.core.md`) forbid declaring a value-producing decoder correct on
self-authored fixtures alone — a decoder and a fixture the same author wrote can
agree while both are wrong (the LZNT1 trap). DPAPI decryption produces a value an
independent tool can check, so a third-party oracle is mandatory, not optional.

**impacket** (`impacket/dpapi.py`) is the de-facto reference implementation of
DPAPI blob/master-key/Vault/Credential decoding in the DFIR community — an
independent third party that authored both the code and, via minted vectors, the
answer key. The step-2 plan pins it explicitly: "Impacket 0.13.1
(`impacket/dpapi.py`) is the independent oracle" (`docs/plans/dpapi-step2.md`).

## Decision

1. **impacket 0.13.1 is the tier-1 oracle** for every decoder. The git history
   shows each landing as a RED test pinned to an impacket-minted vector, then a
   GREEN implementation matched to it:
   - `2e59512`/`8eab064` SHA512/AES-256 blob decrypt "matches impacket"
   - `a19c56a`/`ab17235` master-key file parse + "impacket-anchored derivation"
   - `5b23ec4`/`f0e0a5c` browser `Local State` cookie-key path
   - `5323569`/`10a4148` Credential Manager `CREDENTIAL_BLOB`
   - `71b3593`/`6a6de43` Vault `VPOL`/`VCRD`
   - `6f6935c`/`ebf28dd` Wi-Fi `Wlansvc` `keyMaterial`
2. **Field names and structures mirror impacket** so the differential is
   traceable — `DpapiBlob` "mirrors impacket's `DPAPI_BLOB` structure"; the
   signed byte range is impacket's `rawData[20 .. len - SignLen - 4]`
   (`core/src/blob.rs` doc).
3. **Where impacket implements a path we do not** (RSA domain backup), we refuse
   rather than diverge silently (ADR
   [0006](decisions/0006-master-key-input-refuse-boundary.md)).

## Consequences

- Each decoder's correctness is checkable by anyone with impacket, on the same
  vectors — tier-1 evidence, not self-graded.
- Mirroring impacket's structure/field names keeps the oracle differential cheap
  to re-run and to reason about when a decode diverges.
- The chosen oracle is pinned to a version (0.13.1); a future impacket change to
  a decode path is a deliberate re-anchoring, not a silent drift. A
  `docs/validation.md` write-up of the differential remains outstanding work
  called for by the step-2 plan.
