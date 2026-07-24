# 5. `forbid(unsafe)` and panic-free lints (Paranoid Gatekeeper posture)

Date: 2026-07-24
Status: Accepted

## Context

`dpapi-core` parses untrusted, attacker-controllable bytes: DPAPI blobs,
master-key files, Credential Manager / Vault records, and browser artifacts, any
of which can be malformed or crafted. The fleet Paranoid Gatekeeper standard
(`ronin-issen/CLAUDE.md`) requires such crates to never panic, never read out of
bounds, and never trust a length field, backed by the panic-free lint recipe from
`CLAUDE.core.md`.

Unlike the container readers that mmap an image (ewf, memf), `dpapi-core` is pure
computation over slices callers already hold in memory — it needs no `unsafe` at
all, so the fleet default `unsafe_code = "forbid"` (the provable, badge-able "zero
places a crafted input can corrupt memory") applies without the mmap downgrade to
`deny` + a bounded allow.

## Decision

1. **`unsafe_code = "forbid"`** at the workspace level (root `Cargo.toml`
   `[workspace.lints.rust]`), inherited by both members via `[lints] workspace =
   true`. No `unsafe` anywhere in the tree.
2. **Panic-free denies for the untrusted-input parser**: `unwrap_used = "deny"`
   and `expect_used = "deny"` in `[workspace.lints.clippy]`, plus `correctness`
   and `suspicious` denied. A bad length/key/IV is a typed `DpapiError`, not a
   panic (`core/src/error.rs`, `core/src/decrypt.rs`).
3. **Tests may unwrap** — `clippy.toml` sets `allow-unwrap-in-tests = true` /
   `allow-expect-in-tests = true` (the upstream-recommended exception) so tests
   fail loudly without scattering `#[allow]`.

## Consequences

- `dpapi-core` earns the `unsafe-forbidden` posture (a genuine `forbid`, not
  `deny` + allow), so it may carry the fleet unsafe-forbidden badge, unlike the
  mmap crates.
- Production code cannot silence a decode failure with `.unwrap()`; every
  fallible read returns `Result`, which is exactly what makes the
  refuse-don't-fabricate boundary (ADR
  [0003](decisions/0003-audited-crypto-no-fabrication.md)) enforceable by lint
  rather than by discipline.
- The pragmatic pedantic allows (`cast_possible_truncation`, `similar_names`,
  `too_many_lines`, …) are scoped to priority-1 overrides so the `all`/`pedantic`
  groups still warn everywhere else.
