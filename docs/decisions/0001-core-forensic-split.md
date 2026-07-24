# 1. Two-crate split: `dpapi-core` reader/library + `dpapi-forensic` auditor/CLI

Date: 2026-07-24
Status: Accepted

## Context

The fleet crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") mandates one workspace repo named
`<x>-forensic` with two members: a `<x>-core` reader that owns the raw
parsing/crypto and emits no findings, and a `<x>-forensic` analyzer that consumes
it and emits graded `forensicnomicon::report` findings. The reader is the
low-level, reusable expert; the analyzer is the DFIR-facing tool.

DPAPI has two natural halves that map onto this split cleanly:

1. The byte-format decode and decrypt-given-key crypto — pure, reusable, and
   already needed by a memory tool as well as a disk tool.
2. The on-disk decode + CLI — the examiner's tool. (Its *target* role under the
   fleet standard is filesystem enumeration + graded `forensicnomicon::report`
   findings; see *Current state* below for what actually ships today.)

Git history shows the repo was bootstrapped this way deliberately: `9e52c6c`
"bootstrap dpapi-forensic fleet repo (step 1 — dpapi-core)", then the step-2
commits building the auditor and `dpapi4n6` CLI on top.

## Decision

1. **One workspace, two members** (`Cargo.toml` `members = ["core",
   "forensic"]`): `dpapi-core` (the library) and `dpapi-forensic` (the auditor +
   `dpapi4n6` binary).
2. **`dpapi-core` performs no I/O and emits no findings** — every entry point
   takes `&[u8]` (`core/src/lib.rs`). It owns `blob`, `decrypt`, `chrome`,
   `masterkey`, `credential`, `vault`, `wifi`.
3. **`dpapi-forensic` depends on `dpapi-core`** (`forensic/Cargo.toml`
   `dpapi-core = { workspace = true }`), wires the four store decoders behind the
   `dpapi4n6` CLI, and is where filesystem reads and user-facing reporting live.
4. **The two crates version independently** — `version` is not hoisted into
   `[workspace.package]` (root `Cargo.toml` comment); `dpapi-core` is at `0.2.0`,
   `dpapi-forensic` at `0.2.1`.

## Consequences

- The reusable half (`dpapi-core`) is a standalone crates.io library a memory
  tool, a disk tool, and third parties can link without pulling the CLI, clap,
  serde, or any I/O.
- The split follows the fleet default that `-forensic` builds on `-core`; here
  `-core`'s `&[u8]` API exposes everything the auditor needs, so no
  lower-than-core parsing is required (unlike ntfs/ewf, which drop below their
  reader).
- Independent versioning lets a crypto fix in `dpapi-core` ship without forcing a
  `dpapi-forensic` bump, at the cost of a two-line release instead of one.

## Current state

`dpapi-forensic` today is a **path-taking CLI over `dpapi-core`, not yet the
graded-Finding analyzer the fleet standard calls for.** Concretely:

- Each `dpapi4n6` subcommand takes **explicit artifact paths** — `browser
  --local-state <f> [--cookie <f>]`, `credman --file <f>`, `vault --vpol <f>
  --vcrd <f>`, `wifi --profile <f>` (`Command` in `forensic/src/lib.rs`). It does
  **no** filesystem-tree walking or profile enumeration (an orchestrator or
  `4n6mount` supplies the paths — see `docs/PRD.md` §5).
- Output is **plain typed structs** — `StoreResult` / `CliReport` rendered as text
  or `--json` (`forensic/src/lib.rs`), **not** `forensicnomicon::report::Finding`.
  `forensic/Cargo.toml` carries **no `forensicnomicon` dependency** (only
  `dpapi-core`, `uuid`, `clap`, `serde`, `serde_json`).

The filesystem-enumeration + graded-`forensicnomicon`-findings role remains
planned work (`docs/plans/dpapi-step2.md` steps 3–4; `forensic/Cargo.toml`'s own
description notes "the on-disk auditor … is in progress"). This ADR records the
*split decision*; it does not claim the analyzer half is standard-complete yet.
