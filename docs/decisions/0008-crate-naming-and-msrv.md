# 8. Crate naming (`dpapi-core` / `dpapi-forensic`, import `dpapi_core`) and MSRV floor

Date: 2026-07-24
Status: Accepted

## Context

Two publishing decisions shape how these crates present on crates.io: the crate
names/import paths, and the declared MSRV (`rust-version`, a downstream-facing
promise). The fleet crate-naming grammar and MSRV policy
(`ronin-issen/CLAUDE.md`, `CLAUDE.core.md` "Rust MSRV & Toolchain Policy") govern
both.

Naming: this is a single-format repo (Pattern A), so the grammar gives exactly
two crates — `<x>-core` reader + `<x>-forensic` analyzer. The consumer-facing
import path matters: the grammar keeps `<x>_core` when the bare `<x>` name is a
popular third-party crate rather than hijacking the import.

MSRV: the fleet policy splits by role — apps declare MSRV = the pinned toolchain,
published libraries keep a low, CI-verified floor (`1.75`/`1.80`). This repo pins
its dev toolchain to `1.96.0` (`rust-toolchain.toml`) but declares
`rust-version = "1.85"` for both members (`[workspace.package]`).

## Decision

1. **`dpapi-core` (reader) + `dpapi-forensic` (analyzer + `dpapi4n6` binary)** —
   the Pattern-A two-crate shape (`core/Cargo.toml`, `forensic/Cargo.toml`).
2. **Import path stays `dpapi_core`** — the crate is not published under a `[lib]
   name = "dpapi"` override; README and `forensic/src/lib.rs` write `use
   dpapi_core::…`. This follows the grammar's "do not hijack a popular bare name"
   rule (`dpapi` is an unrelated third-party crate on crates.io). *Rationale for
   the specific collision reconstructed from the grammar; the original intent was
   not restated in commit history.*
3. **Declared MSRV `1.85`, uniform across both members**, decoupled from the
   `1.96.0` dev toolchain pin. A single `[workspace.package] rust-version` covers
   the library and the CLI.

## Consequences

- Consumers write `use dpapi_core::…` regardless of the crates.io package name,
  and the analyzer name (`dpapi-forensic`) does not over-claim or collide with the
  repo name.
- `dpapi-core` is a published library whose declared floor (`1.85`) is higher than
  the fleet's usual library floor (`1.75`/`1.80`), which narrows its crates.io
  audience. **The specific driver for `1.85` (a dependency's MSRV, an edition/std
  feature, or a deliberate uniform-with-CLI choice) is not recovered in available
  history — rationale reconstructed from structure; original intent not recovered
  in available history.** If no dependency actually requires `1.85`, lowering the
  library floor toward `1.80` and CI-verifying it would restore the fleet
  low-MSRV promise; that is a follow-up to confirm, not a change made here.
- The dev/toolchain pin (`1.96.0`) and the downstream MSRV promise (`1.85`) are
  correctly kept separate, per policy.
