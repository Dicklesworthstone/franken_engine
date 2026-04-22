# Dependency Upgrade Log — franken_engine

**Date:** 2026-04-21
**Language:** Rust (edition 2024, nightly toolchain)
**Workspace:** 6 crates (`franken-engine`, `franken-extension-host`, `franken-engine-test-support`, `franken-metamorphic`, `franken-core`, plus `fuzz/` side workspaces)

## Summary

- **Updated (registry switch):** 3 direct (`franken-kernel`, `franken-decision`, `franken-evidence`) from local path deps to crates.io 0.3.1
- **Updated (lockfile, semver-compat):** 17 transitive bumps via `cargo update`
- **Skipped (major bump — needs user authorization):** `rand` 0.8 → 0.10, `sha2` 0.10 → 0.11, `hmac` 0.12 → 0.13, `toml` 0.8 → 1.1
- **At latest:** `chrono` 0.4.44, `clap` 4.6.1, `uuid` 1.23.1

## Updates

### franken-kernel / franken-decision / franken-evidence: path="/dp/asupersync/*" → 0.3.1 (crates.io)

- **Breaking:** None at call sites.
- **Motivation:** Removes the hard requirement for a sibling `/data/projects/asupersync` checkout. 0.3.1 is the first crates.io release with the stable trait surface the `asupersync-integration` feature consumes.
- **File:** `crates/franken-engine/Cargo.toml`
- **Transitive consequence:** asupersync 0.3.1 family uses RustCrypto 0.11 (`digest` 0.11, `hmac` 0.13, `block-buffer` 0.12, `crypto-common` 0.2, `hashbrown` 0.17, plus new transitive crates `cmov`, `const-oid`, `ctutils`, `hybrid-array`). They land in Cargo.lock alongside the existing direct 0.10-era deps; both coexist.
- **Tests:** `cargo check -p frankenengine-engine` clean.
- **Commit:** `a79320e5` (`deps: switch franken-kernel/decision/evidence from local path to crates.io 0.3.1`)

### cargo update — 17 transitive bumps, no manifest edits

- `hashbrown` 0.16.1 → 0.17.0
- `indexmap` 2.13.0 → 2.14.0
- `itoa` 1.0.17 → 1.0.18
- `js-sys` 0.3.86 → 0.3.95
- `libc` 0.2.182 → 0.2.185
- `once_cell` 1.21.3 → 1.21.4
- `quote` 1.0.44 → 1.0.45
- `r-efi` 6.0.0 added
- `rand` 0.8.5 → 0.8.6 (direct); `rand 0.9.4` coexists transitively
- `semver` 1.0.27 → 1.0.28
- `typenum` 1.19.0 → 1.20.0
- `uuid` 1.21.0 → 1.23.1
- `wasip2` 1.0.2 → 1.0.3
- `wasm-bindgen` 0.2.109 → 0.2.118 (+ macro, macro-support, shared)
- `winnow` 0.7.14 → 0.7.15
- `wit-bindgen` 0.57.1 added
- `chrono` resolved at 0.4.44, `clap` at 4.6.1 (specs already allowed)

4 deps remain "behind latest" because of compat constraints elsewhere in the graph.

- **Tests:** `cargo check -p frankenengine-engine` clean.
- **Commit:** `93b122a9` (`deps: cargo update within semver (transitive lockfile refresh)`)

## Needs Attention — requires user decision

### rand: 0.8.6 → 0.10.1 (MAJOR, spans 2 major versions)

- **Scope:** Breaking API. `rand 0.9` removed `thread_rng()` in favor of `rng()`, renamed `Rng::gen` to `Rng::random`, reshaped `Rng::gen_range` and `SeedableRng`. `rand 0.10` continued the churn.
- **Call sites in franken_engine:** 2 files (`crates/franken-core/src/signature_preimage.rs`, `crates/franken-engine/src/signature_preimage.rs`) — under the 20-file circuit breaker, but both are security-relevant (signature generation). Bump-in-isolation feasible; require extra review eyes.
- **Status:** Deferred.

### sha2: 0.10.9 → 0.11.0 (MAJOR)

- **Scope:** Breaking API. RustCrypto 0.11 digest trait family.
- **Call sites in franken_engine:** **>100 files** across `franken-engine`, `franken-extension-host`, `franken-metamorphic`, `franken-core` (Grep output hit the 100-file head limit).
- **Circuit breaker triggered** (>20-file refactor): deferred pending explicit authorization.
- **Note:** asupersync 0.3.1 family already pulled in `digest 0.11.2` transitively. Direct `sha2 0.10.9` stays in the graph until the main-crate migration.

### hmac: 0.12.1 → 0.13.0 (MAJOR)

- **Scope:** Breaking API (aligned with RustCrypto 0.11). `new_from_slice` kept but digest type bounds changed.
- **Call sites in franken_engine:** 2 files (`crates/franken-core/src/hash_tiers.rs`, `crates/franken-engine/src/hash_tiers.rs`). Under the 20-file limit; would bundle with the sha2 0.11 migration.
- **Status:** Deferred.

### toml: 0.8.23 → 1.1.2 (MAJOR, 1.0 release)

- **Scope:** Reshuffled `toml::from_str` / `toml::Value` / serde integration in 1.0.
- **Call sites in franken_engine:** 11 files. Under the 20-file limit but borderline.
- **Status:** Deferred.

## Skipped / Preserved

- `frankenengine-extension-host`, `frankenengine-test-support`, `franken-core`, `franken-metamorphic` — path deps (sibling workspace members).

## Environment

- Verified build host: Ubuntu 24.04 LTS, Linux 6.17.0-22-generic
- Toolchain: rustc 1.95.0-nightly (7f99507f5 2026-02-19)
- Build dir override: `CARGO_TARGET_DIR=/data/tmp/franken_engine_target` (root `target/` is immutable on this host — `sbh` disk-pressure guard)
- `cargo audit` not run yet (deferred; wire into CI before the 0.11 sha2 migration).
