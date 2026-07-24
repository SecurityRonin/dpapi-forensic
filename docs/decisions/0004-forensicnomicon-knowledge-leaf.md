# 4. DPAPI format constants live in `forensicnomicon`; depend on the published registry crate

Date: 2026-07-24
Status: Accepted

## Context

DPAPI parsing needs a set of format *facts*: the provider GUID that identifies a
DPAPI blob, the `CALG_*` hash/cipher algorithm IDs and their block-size/param
descriptors (impacket's `ALGORITHMS_DATA`), and the Chrome `v10`/`v20` prefixes.
The fleet layer architecture puts such format constants in the KNOWLEDGE leaf,
`forensicnomicon` — a zero-dependency crate every analyzer depends *down* onto,
never one that parses or does I/O (`ronin-issen/CLAUDE.md`, "forensicnomicon"
responsibilities; dependency rule "PARSER depends on KNOWLEDGE only").

The history shows this settling in stages, not in one shot:

- `8fc7f4a` "drop unused forensicnomicon dep (decouples dpapi-core publish)" —
  the dep was initially declared but unused, and was removed so `dpapi-core`
  could publish independently.
- `18d3c86` "forensicnomicon dep path → registry 0.10 (now published)" — once
  the needed constants shipped in a published `forensicnomicon`, the dep was
  re-added, pointing at the crates.io registry version rather than a local path.
- `7b1324f` "source DPAPI magic from forensicnomicon knowledge crate" and
  `8c66188` reject blobs whose provider GUID isn't DPAPI — the parser then
  consumes those constants.

## Decision

1. **DPAPI magic numbers live in `forensicnomicon::dpapi`**, not in `dpapi-core`:
   `PROVIDER_GUID_BYTES`, `hash_alg_info`/`HashAlgInfo`, `cipher_alg_info`,
   `CALG_AES_256`, and the Chrome prefixes (`core/src/blob.rs`,
   `core/src/decrypt.rs` imports). `dpapi-core` owns only the parsing + crypto
   that *consume* those facts.
2. **Depend on the published registry crate, not a path dep** — root
   `Cargo.toml`: `forensicnomicon = "1"`. This follows the fleet rule "prefer the
   published registry crate over a `path` dependency once it is on crates.io"
   (reproducible, decoupled from local checkout layout).
3. **Reject a blob whose provider GUID isn't DPAPI** at parse time (`8c66188`),
   using the KNOWLEDGE-leaf `PROVIDER_GUID_BYTES` — fail loud on a
   non-DPAPI/foreign blob rather than mis-decode it.

## Consequences

- Format facts are shared fleet-wide: a `CALG_*` addition or a corrected block
  size is a `forensicnomicon` change every consumer inherits, not a per-crate
  copy that drifts.
- `dpapi-core`'s publishability was preserved through the transition — it briefly
  carried no `forensicnomicon` dep at all rather than block on an unpublished
  KNOWLEDGE crate, then adopted the registry version once available.
- The two distinct block-size fields (`derive_block_len` vs `hash_block_len`)
  that impacket conflates in practice are documented and separated at the
  KNOWLEDGE boundary (`core/src/blob.rs` doc), preventing a subtle
  wrong-block-size bug.
