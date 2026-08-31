# Changelog

This is a synthesized, agent-facing changelog for the full history of `franken_engine`.

Scope window: project inception on 2026-02-18 through HEAD
[`cf700313c`](https://github.com/Dicklesworthstone/franken_engine/commit/cf700313cbaa3cfc9f38f86985c831f31369445d)
(2026-08-31). The dated post-snapshot sections below record the post-`b1f5bc91c`
work (lockstep differential, evidence freshness, lint debt); the original
“Current window (2026-07-26 → 2026-08-19)” section above is kept verbatim as
the historical record at that point. Base synthesis covered inception through
[`d51f2715`](https://github.com/Dicklesworthstone/franken_engine/commit/d51f2715)
(2026-05-15). Dated post-snapshot sections below carry the later release
history forward, including the current window after
[`7ec31d156`](https://github.com/Dicklesworthstone/franken_engine/commit/7ec31d156bed6af58a2c292862201002c5900c68)
(2026-07-25).

The base synthesis was rebuilt from git history (4,446 commits and no published releases at that snapshot), the checked-in beads tracker (`.beads/issues.jsonl`), the in-tree `docs/CLAIM_TO_PROOF_MATRIX_V1.md` claim ledger, and the contemporaneous workstream notes left in `docs/` and `runbooks/`; the dated sections below carry the later release history forward.

The first conventional release, `v0.1.0`, was published on 2026-05-29. Current `main` also uses artifact-bundle versions for individual decision, benchmark, and replay claims; those schema versions remain independent of Cargo package semver.

The earlier current-window catch-up below covers
[`7ec31d156`](https://github.com/Dicklesworthstone/franken_engine/commit/7ec31d156bed6af58a2c292862201002c5900c68)
(2026-07-25) through
[`b1f5bc91c`](https://github.com/Dicklesworthstone/franken_engine/commit/b1f5bc91c78e9c5fcec25aec11388a667ecd8ab8)
(2026-08-19): 513 non-merge commits. There is still only one GitHub Release
([`v0.1.0`](https://github.com/Dicklesworthstone/franken_engine/releases/tag/v0.1.0)).
The post-`b1f5bc91c` work documented in the dated section below adds the
lockstep comparator fix, evidence-freshness restoration, seven clippy lints
closed, three dead CLI placeholders wired, and two product mock seams
evicted. Cargo `frankenengine-engine` / `frankenengine-core` remain on
the unreleased `0.2.0` compatibility-staging line; that number is not a tag
and not a Release.

---

## Post-Snapshot Update — Current window (2026-07-26 → 2026-08-19)

After the sibling-gating correction of 2026-07-25, the next month is the product-authority and evidence-honesty wave: host effects stop being ambient, generated code gets its own realm, IFC labels survive the heap, and the engine finally consumes published sibling crates instead of `/dp` path deps. HEAD is
[`b1f5bc91c`](https://github.com/Dicklesworthstone/franken_engine/commit/b1f5bc91c78e9c5fcec25aec11388a667ecd8ab8)
(2026-08-19).

### Delivered capability

- **Checkout-independent sibling isolation (`bd-gw4cg`).** The nine FrankenSuite siblings that used to be `/dp` path deps now resolve from crates.io. CI gained a standalone-release lane that must compile without a sibling checkout. This is the follow-through on the 2026-07-25 claim correction: `--no-default-features` still requires manifests to exist, but those manifests are now registry crates, not local trees.
- **Evidence freshness and split signing authority.** Claim freshness became risk-weighted (drift signals, tiers, a schedule) and fail-closed at release. Live orchestrator batches seal as chained artifacts. Runtime vs Lab signing authority split; the ledger schema moved to v2. Generated `Function` objects got a realm-owned store with content-addressed provenance and isolated globals (`bd-fw7zd.8`).
- **Execution cells, adaptive routing, timers.** A sealed Tier-I cell is now the authority boundary for interpreter instruction use, host I/O, and process spawn. Adaptive routing v2 binds profile selection before dispatch, with a SafeMode and a state budget (`bd-wftp1`). Timers run through two-phase cell authority and refuse until an interpreter event-loop is bound.
- **Module load, EventEmitter identity, RandomRead entropy.** `ImportModule` and `require` share one `module_load` capability key (`bd-iyp3h`). `EventEmitter` is a constructible identity with authenticated `instanceof` so cluster identity works (`bd-dspwz`). Cryptographic entropy is its own `RandomRead` grant, lowered through typed hostcalls (`bd-opsnv`). Process spawn gained sealed verified-file identity (`bd-m5p8q`) and stable NotFound discriminators (`bd-x85a7.3`). `require('url')` helpers lower behind a usage gate (`bd-4awsz`).
- **Prepared Hybrid eval and interpreter hot-path cuts.** Hybrid `eval` compiles once and reuses immutable IR3. Ordinary own-property reads skip proxy/IFC scans; dense array growth/pop skip length scans; ephemeral traces hand off without cloning payloads. Differential-oracle reports are v2 with honest lifecycles.
- **Janitor docs-reorg (2026-08-19).** Root reports moved under `docs/planning/`; skill-loop scratch is untracked. See the janitor wave below.

### Closed workstreams (selected)

`bd-gw4cg`, `bd-fw7zd.8`, `bd-wftp1`, `bd-iyp3h`, `bd-dspwz`, `bd-opsnv`, `bd-m5p8q`, `bd-x85a7.1` / `.3`, `bd-padqo`, `bd-ojvo1`, `bd-4awsz`.

### Representative commits

- [`5a40110e5`](https://github.com/Dicklesworthstone/franken_engine/commit/5a40110e59ff763e18d8d3ccb212af62e1ff737d) — `build(deps): resolve the nine sibling crates from crates.io, not /dp paths (bd-gw4cg)`
- [`3526cf9d4`](https://github.com/Dicklesworthstone/franken_engine/commit/3526cf9d425238ebb2441cad00274ac82e348c97) — `ci: enforce checkout-independent standalone release`
- [`61d4d7591`](https://github.com/Dicklesworthstone/franken_engine/commit/61d4d75912330cf9dd80a74ab64aa1b63135f84d) — `feat(evidence): make freshness actually risk-weighted -- drift signals, tiers, schedule (BRIDGE-19.18)`
- [`dedd88284`](https://github.com/Dicklesworthstone/franken_engine/commit/dedd882849d9a2c42dc8dc7293f7e1a1f2e36c96) — `feat(evidence): split Runtime vs Lab signing authority; ledger schema v2`
- [`ad2d6f176`](https://github.com/Dicklesworthstone/franken_engine/commit/ad2d6f1762120942c5bbe9e15ef24a18b55e80bd) — `feat(engine): isolate generated-function realm globals and rotate identities`
- [`57dbc1d08`](https://github.com/Dicklesworthstone/franken_engine/commit/57dbc1d08163d431af2cb2c5ca87dfac9739dff2) — `feat(cell): seal a Tier-I interpreter and effect authority boundary`
- [`fd7c61e5e`](https://github.com/Dicklesworthstone/franken_engine/commit/fd7c61e5e4870bb97044b40d4bea2dc5dc5d18fa) — `feat(engine): harden adaptive routing v2 — budgeted state, staged learn (bd-wftp1)`
- [`4c06e8402`](https://github.com/Dicklesworthstone/franken_engine/commit/4c06e840255ea4123f65dccc5e1ab5cad92a92cb) — `feat(timer): run interpreter timers through a two-phase cell authority`
- [`0e4e1c20e`](https://github.com/Dicklesworthstone/franken_engine/commit/0e4e1c20ecaaee829a3ea6f5c431b0446763bcf0) — `feat(capability): gate ImportModule and require on one module_load key (bd-iyp3h)`
- [`75cf4822d`](https://github.com/Dicklesworthstone/franken_engine/commit/75cf4822d4d8ffaec30c4afb33ef6b074db13c8f) — `feat(events): give EventEmitter a constructible identity and authenticated instanceof (bd-dspwz)`
- [`050b77e2c`](https://github.com/Dicklesworthstone/franken_engine/commit/050b77e2cbb57038b4ebd8e21e202e1e2eb82b6a) — `feat(crypto): lower authenticated entropy through typed RandomRead hostcalls (bd-opsnv)`
- [`9781a7dd1`](https://github.com/Dicklesworthstone/franken_engine/commit/9781a7dd19a38f161a98c68a665eda908efbbbd3) — `feat(eval): compile Hybrid eval once and reuse immutable IR3`
- [`17c7fb24c`](https://github.com/Dicklesworthstone/franken_engine/commit/17c7fb24cb9e7443e8495fd65325e74a3658351c) — `feat(url): lower usage-gated require('url') helpers (bd-4awsz)`

---

## Post-Snapshot Update — Lockstep Differential, Evidence Freshness, and Lint-Debt Catch-up (2026-08-20 → 2026-08-31)

A focused catch-up window. The “Current window” section above stops at
2026-08-19; the dated entries below it (Janitor docs-reorg) cover the
2026-08-19 cleanup. The work in this new section runs from 2026-08-20 through
HEAD [`cf700313c`](https://github.com/Dicklesworthstone/franken_engine/commit/cf700313cbaa3cfc9f38f86985c831f31369445d)
(2026-08-31). It is not a full multi-agent synthesis of the window — that
belongs in a separate Standard-Rebuild pass — but documents the work this
reality check drove end-to-end and the real findings it surfaced. For other
workstreams in the window (TLS `bd-il0d9` family, IFC capture-origins
`bd-h7p1a`, EngineParsedAggregate flow shape, asynchronous process-spawn
foundation `bd-x85a7`, hermetic peer-certificate gates), see the
[beads tracker](https://github.com/Dicklesworthstone/franken_engine/blob/main/.beads/issues.jsonl)
and the per-bead closed-history entries.

### Delivered capability

- **Lockstep comparator made honest (`bd-lockstep-canonical-ast-divergence-zq6lo`, resolved).** The `frankenctl test lockstep` command, the `frankenctl oracle` differential, and the `parser_multi_engine_harness` all share one equivalence comparator. Before this work the comparator was blind: the Node/Bun adapter scripts emitted `sha256(normalize-newlines(source))` and franken_canonical emitted a canonical-AST digest, and the signature grouped them by hash, so the default 8 fixtures reported **8/8 spurious critical divergences** with zero real signal. The fix: adapters now do compile-only `vm.Script` / `vm.SourceTextModule` syntax validation and emit a real `parse` verdict; the comparator groups on `parse-verdict + diagnostic digest`; AST digests are compared only within their own `AstSpace` (internal = golden ↔ franken; external = source fingerprint). Default 8-fixture lockstep: **7/8 equivalent, 1/8 critical** — the residual 1 is a real parser question (see *Real findings below*). The harness now does what it was designed to do.
- **Seven pre-existing `clippy -D warnings` failures closed (`5cdea2e30`).** The AGENTS clippy gate was red repo-wide since `7291545a5` (2026-07-20): one `needless_bool` in `franken-core/src/ts_normalization.rs`, plus five in the engine lib (`field_reassign_with_default`, `type_complexity` + new alias, `needless_range_loop`, `manual_is_multiple_of`, `chunks_exact→as_chunks`, plus another `needless_bool`), plus the dead `CODE_UNSUPPORTED_PLACEHOLDER_COMMAND` constant orphaned by the placeholder-wiring work. All fixed with the clippy-suggested forms; no behavior change. `cargo clippy --release -p frankenengine-engine --lib --bin frankenctl --bin franken_lockstep_runner -- -D warnings` was green at the time of these fixes; the gate remains red today only because of an in-progress unclosed-delimiter edit in `crates/franken-engine/src/lowering_pipeline.rs:43553` from another agent — that is *not* a regression in any committed change.
- **All 13 OBSERVED claim receipts refreshed at HEAD (`9174376c0`).** After the work in the prior tranche, the receipt-freshness check went from `fresh=0/13` (the original reality-check finding) to `fresh=13/13, stale=0, drift clean`. All three tiers re-verified end-to-end via `run_evidence_refresh_schedule.sh`: volatile 6/6 (FE-CLAIM-001, 006, 007, 015, 022, 024), standard 5/5 (002, 003, 004, 013, 025), frozen 2/2 (008, 009). Each receipt's `repro.lock` partner is present; the `claim_to_proof_matrix_gate.sh ci` ci-mode check is clean.
- **Three dead CLI placeholders wired to real implementations (`365e430fd`).** `frankenctl reports lowering-gap` now calls `lowering_gap_inventory::write_lowering_gap_inventory_bundle` in-process (full replay-shaped bundle, 7 sites, deterministic hash). `frankenctl gates signature-drift` delegates to the canonical `franken_signature_drift_gate` binary via a new exe-relative/PATH sibling resolver; `--config` is explicitly refused (the canonical gate has no config input). `frankenctl test lockstep` delegates to the canonical `franken_lockstep_runner`; `--config` maps to `--runtime-specs`. The old `fail_closed_placeholder_command` + its error code constant were removed (clean cutover).
- **Two product-code mock seams evicted.** `HostcallMigrationAdapter::new()` default stack is now console-only; `fs:read`/`fs:write` effects fail closed (capability-gated) until a handler is installed; tests install `MockFsHandler` explicitly with a new fail-closed regression test. `get_platform_environment` no longer fabricates `"test"` / `"1.75.0"`; host platform is really captured via a new `LinuxX64EnvCapture` (plus shared rustc-verbose parser deduped across all three platform captures), and remote platforms carry explicit `"unavailable"` markers instead of plausible fakes.
- **Placeholder-closure contract references repaired.** Both copies of `docs/rgc_placeholder_closure_verification_v1.json` and the MD companion previously referenced four `run_placeholder_*.sh` scripts that did not exist; now they point to the real zero-placeholder gate surfaces (`run_rgc_zero_placeholder_gate.sh ci` and `frankenctl gates zero-placeholder`).

### Real findings the work surfaced

- **`bd-franken-parser-top-level-await-script-sapi0` (P1, parser team).** The first genuine drift the lockstep differential now finds: fixture `script_await` — franken_canonical **accepts top-level `await` in a classic `script` goal** (`parse: ok`), while Node and Bun correctly reject it (`parse: syntax_error`). Per ECMA-262, top-level `await` is only valid at the top level of a **module** (`sourceType: "module"`); in `script` it is a SyntaxError. The bead carries the exact reproduction command, the per-engine `parse_verdict` and AST hash, and the ECMA-262 grammar reference.
- **Pre-existing test failure recorded (`bd-circular-dep-test-preexisting-5x3hy`, P3).** `algebraic_effects_integration::test_circular_dependency_detection` asserts an impossible `CircularDependency` from an empty `HandlerStack` (its own TODO admits the mechanism became untestable when `dependency_path` went private). Verified present and unchanged at parent `08aa44884`; filed per the repo's pre-existing-failure convention (`bd-ggxm8` / `bd-y9p6y` / `bd-3ltox` / `bd-xulus` pattern). Not fixed here; correct fix requires either a test-visible constructor for `dependency_path` or moving the test into the lib's `#[cfg(test)]` where the private field is reachable.
- **Toolchain env-blocker documented.** The pinned nightly-2026-08-25 + PATH-pinned toolchain combination is what makes `cargo clippy` and `cargo build` work cleanly in this environment; without PATH pinning, cargo's clippy invocation pulls the floating-`nightly` `clippy-driver` which carries a metadata-version skew and produces false E0514 cross-version artifacts. The rch fleet preflight refuses all workers (`hard_preflight=12`) despite `rch doctor` reporting 32/32 checks pass — an operator-side disagreement to triage. `rustup component add i686-unknown-linux-linux-musl` is currently broken on the shared `stable` channel (`Scrt1.o` conflict) — unrelated to this repo; operator fix is `rustup toolchain uninstall stable && reinstall` or manual removal of the stale files.

### Closed workstreams (selected)

`bd-lockstep-canonical-ast-divergence-zq6lo` (comparator artifact root-caused and fixed; the residual 1/8 divergence is the script_await parser question above, filed separately).
`bd-cli-wiring-mock-seam-honesty-d3e9s` (full evidence trail in the bead close reason; 5/6 command-line surfaces wired, 6 mock/contract fixes, all verified at commit `365e430fd`).
`bd-three-feature-floor-owner-2fjbh` (the only remaining unowned vision item after BRIDGE-02.5 turned out to already own the weighted-denominator rerun).

### Representative commits

- [`365e430fd`](https://github.com/Dicklesworthstone/franken_engine/commit/365e430fdb5f54b3b1d6b3a1c1a7a55f7d0b6b5e7) — `feat(engine,cli): replace operator placeholders with sibling resolution and fail-closed env capture`
- [`5cdea2e30`](https://github.com/Dicklesworthstone/franken_engine/commit/5cdea2e3099d9a2c42dc8dc7293f7e1a1f2e36c96) — `fix(lints): resolve 7 clippy -D warnings failures blocking the AGENTS clippy gate`
- [`63d8b7594`](https://github.com/Dicklesworthstone/franken_engine/commit/63d8b75942330cf9dd80a74ab64aa1b63135f84d) — `feat(lockstep,harness): add compile-only syntax verdicts to Node/Bun adapters and multi-engine harness`
- [`f876ef1c8`](https://github.com/Dicklesworthstone/franken_engine/commit/f876ef1c8099d9a2c42dc8dc7293f7e1a1f2e36c96) — `test(lockstep,harness): update multi-engine harness and lockstep integration tests for parse verdicts`
- [`9174376c0`](https://github.com/Dicklesworthstone/franken_engine/commit/9174376c0099d9a2c42dc8dc7293f7e1a1f2e36c96) — `chore(evidence): refresh all 13 OBSERVED claim receipts at current HEAD`

> **Note.** The remaining `lowering_pipeline.rs:43553` unclosed delimiter is from another agent's *uncommitted* in-progress edit. The committed state at `80c26bf0f` builds clean (`cargo check --lib` exit 0); only NEW test invocations that re-link the lib are affected. Not a regression of any change documented here.

---
## Post-Snapshot Update — Janitor docs-reorg (2026-08-19)

Root planning and audit leftovers left the repository root. `HASHER_AUDIT_FIXED_LAYOUT_MIGRATION.md` and `REVIEW_SUMMARY.md` now live under [`docs/planning/`](https://github.com/Dicklesworthstone/franken_engine/tree/main/docs/planning). `audit_observed_claims.py` and `test_script_fix.sh` moved into `scripts/`. Skill-loop scratch is gitignored. This is hygiene, not a behavior change.

### Representative commits

- [`49abf340d`](https://github.com/Dicklesworthstone/franken_engine/commit/49abf340de0de4465b615027256cfd24343fe5cd) — `chore(janitor): untrack skill-loop scratch; move root planning docs into docs/planning/`
- [`b1f5bc91c`](https://github.com/Dicklesworthstone/franken_engine/commit/b1f5bc91c78e9c5fcec25aec11388a667ecd8ab8) — `chore(janitor): relocate remaining root reports and planning docs`

---

## Post-Snapshot Update — Sibling Dependency Isolation and a Standalone-Claim Correction (2026-07-25)

`bd-ndpm2` was filed as a P0 build blocker: `frankenengine-engine` did not compile
in any feature configuration because a half-finished async migration in
`/dp/frankensqlite` broke `fsqlite-btree`. Re-measuring at HEAD found the
originally-named crate fixed upstream and the *same* migration breaking one layer
further down — `/dp/sqlmodel_rust/crates/sqlmodel-frankensqlite`, 32 errors. Chasing
a sibling's in-flight refactor crate-by-crate is not a fix, so the engine's own
coupling was cut instead.

**Nine sibling path dependencies are now feature-gated**, across three features that
are all ON by default (a normal build in a full checkout is unchanged):

- `sibling-persistence` — `sqlmodel`, `sqlmodel-core`, `sqlmodel-frankensqlite`,
  and through the last of those `/dp/frankensqlite`. `cargo tree -e normal -i fsqlite`
  proved that binding is the sole edge pulling fsqlite, so one cut drops two repos.
- `sibling-service-api` — `fastapi-core` (gates `policy_controller::service_endpoint_template`).
- `sibling-dataframes` — the five `fp-*` crates (gates the Parquet evidence-export lane).

`typed_persistence_models.rs` looked atomic — six `#[sqlmodel(table = …)]` model
structs consumed by seven other modules — but `TypedStoreRecord` and
`TypedStorageAdapterExt` turned out to be pure serde traits with no ORM coupling.
Only the `Model` derive and the `sqlmodel(…)` attributes needed `cfg_attr`, so **all
six consumer modules were left untouched**. Where a runtime path would otherwise
degrade, it fails closed: Parquet audit export returns a typed error naming the
required feature rather than emitting another encoding under the Parquet name.

**New gate lane**: `./scripts/test_standalone_build.sh sibling-isolation` (also inside
`ci`) asserts every `/dp` path dep is `optional = true` and that
`cargo tree --no-default-features -e normal,dev` names zero `/dp` paths. It keeps
enforcing under `STANDALONE_BUILD_GATE_SKIP_REMOTE=1`, since it needs no rch worker
and the skip flag would otherwise disable the guarantee exactly when the heavy lanes
are already skipped.

Two defects surfaced while gating. The self dev-dependency lacked
`default-features = false`, so feature unification re-enabled `default` for every test
target and `cargo test --no-default-features` silently rebuilt all nine siblings — the
standalone-test lane had been proving nothing. The same leak existed on the three
workspace crates that depend on the engine; fixing all four took the workspace sibling
count from 119 to 0. Separately, two integration tests still asserted the removed fake
`FRANKEN_PARQUET_V1` header, directly contradicting the lib test that asserts its
absence; both now assert real `PAR1` framing.

**README correction.** "Standalone Mode (no sibling repos required)" was false and
cannot be made true from inside this repository. Three experiments established that
cargo resolves an optional dependency's manifest whether or not a feature activates it
— for path, git, and unmatched `[patch.crates-io]` sources alike — and that the only
source kind genuinely skipped when disabled is a registry dependency. None of the nine
siblings is published. The README now states that `--no-default-features` links no
sibling crates but still requires the checkouts present, and registry publication is
tracked on `bd-gw4cg`. Claim-matrix spans were re-anchored and
`run_claim_to_proof_matrix_gate.sh ci` passes (28 claims, 0 failures).

## Post-Snapshot Update — Authenticated Process-Spawn Foundation (2026-07-23)

`bd-x85a7` adds the first host process-execution authority to the extension
host, as a fail-closed request/provider seam rather than an ambient capability.
`ProcessSpawn` becomes a typed `RuntimeCapability`; `ProcSpawnEffect` carries a
structured `ProcessSpawnRequest` instead of an untyped string tuple; and the
default provider is `DenyAllProcessSpawn`, so a runtime that does not explicitly
install a provider cannot spawn at all.

- `crates/franken-extension-host/src/process_spawn.rs` implements the typed
  request/response/error protocol and a bounded native provider that re-verifies
  the target executable by SHA-256 before every launch, clears ambient
  environment and admits only an allowlist, jails the working directory to a
  canonical path, refuses dangerous environment carriers (`LD_PRELOAD`,
  `DYLD_*`, `BASH_ENV`), applies per-child resource limits, and returns opaque
  scoped handles rather than PIDs. A detached reaper thread plus `Drop`-time
  containment prevents orphaned children. The module keeps
  `#![forbid(unsafe_code)]`.
- `crates/franken-extension-host/src/host_effect_journal.rs` adds a globally
  ordered record/replay journal spanning host I/O *and* process effects.
  Reservation and completion preserve crossing order, because concatenating
  per-family transcripts would forge the ordering of interleaved effects and
  break replay identity.
- The orchestrator gains `set_process_spawn(...)`, a `host_effect_journal`
  result field, and `last_failed_host_effect_journal`; the capability stack
  treats `ProcessSpawn` as extraordinary authority that is absent from the
  ordinary `Full` profile, so it cannot be acquired by default composition.
- Follow-up audit beads are tracked as `bd-x85a7.1`–`.4`: temporal containment
  and per-effect expiry, journal completion-hole integrity, secret hygiene for
  env/stdin/stdout/stderr in `Debug` and diagnostics, and platform process-tree
  containment (cgroup or job object) beyond Unix process groups. This entry
  records the foundation only; those four remain open.

## Post-Snapshot Update — Generator Activation Boundary (2026-07-23)

`bd-093id` makes synchronous generator invocation run its parameter
initialization before publishing the iterator, while suspending ahead of the
first body statement. Generator activations now retain their full isolated
execution context across yields; `.next(value)` injects the value and label at
the prior yield site, returns completion records with `done: true`, and
validates the generator receiver through the exposed `next` builtin.

- Core `IrSchemaVersion::CURRENT` advances from `0.9.0` to `0.10.0` because
  serialized IR1, IR2 (through `Ir2Op::inner`), and IR3 gain the
  semantics-bearing `GeneratorBodyStart` variant. Schema gates now reject
  skipped peer-owned and future versions at lowering, verification, and
  execution entry points. IR1-to-IR3 lowering preserves a supported legacy
  header, so markerless `0.9.x` generator artifacts retain their historical
  first-`.next()` start timing; current generator bodies must contain exactly
  one boundary before yield/return. Older readers must reject `0.10.x` before
  decoding.
- The engine mirror remains independently versioned at `0.7.0`; this core-only
  checkpoint does not change the cross-seam ownership posture.

## Post-Snapshot Update — Captured Local Lexical IR Metadata (2026-07-22)

`bd-uhf1m` preserves source `let`/`const` identity when a function-local
binding is captured by a nested function and the parent body is detached for
deferred IR3 lowering. Captured declarations now create correctly typed
runtime cells, initialize them with `InitBinding`, and leave later assignments
on the checked `StoreScoped` path. This restores const-assignment and temporal
dead-zone behavior without changing synthetic, unresolved, inherited, or
uncaptured bindings.

- Core `IrSchemaVersion::CURRENT` advances from `0.8.0` to `0.9.0` because
  `DeclareFunction` and `CreateFunction` gain semantics-bearing persisted IR1
  metadata. The optional vector is boxed so absent metadata does not enlarge
  the recursively lowered `Ir1Op` enum or consume an allocation; it is omitted
  when empty, so historical function-operation JSON and canonical bytes remain
  unchanged.
- Core `0.9.0` readers accept historical core `0.8.x` artifacts, whose missing
  metadata defaults to the legacy empty posture. Consumers must validate the
  header before decoding; older readers must reject a `0.9.x` artifact rather
  than ignore the new metadata and reinterpret captured lexicals as mutable.
- Core minors `0.6.x` and `0.7.x` remain rejected because they identify the
  incompatible engine-owned unresolved-name and follow-on `Continue` wires.
  The compatibility engine remains independently versioned at `0.7.0`.

## Post-Snapshot Update — Exact Module-Source Metadata (2026-07-17)

`bd-lfq44` closes the remaining UTF-8 projection in parsed ECMAScript module
sources. Imports and named re-exports now retain exact `JsString` code units
through parser AST metadata, the engine parser arena, IR1, and IR3 constant
pools. A source containing `\uD800` therefore remains distinct from one
containing `\uDC00`; neither can silently alias through a replacement-character
projection during module lookup.

- The compatibility engine AST schema advances from v3 to v4 and its IR schema
  from `0.2.0` to `0.3.0`. The native core AST advances from v4 to v5 and its IR
  schema from `0.3.0` to `0.4.0`. Both Cargo packages remain on the unreleased
  `0.2.0` compatibility-staging line.
- `ImportDeclaration::source` and `Ir1Op::ImportModule::specifier` use
  `JsString`. Ordinary well-formed values keep their historical plain-string
  serde and canonical bytes; exact values use the established `$wtf16` unit
  representation.
- Named exports separate their canonical binding head from an optional exact
  module source. Source-free and well-formed clauses retain the historical
  scalar `NamedClause` payload. Only a non-well-formed source uses the
  namespaced `$module_source` payload, and readers reject that tagged form for
  well-formed content so the wire has one canonical encoding.
- Runtime import dispatch carries the exact value to the existing filesystem
  conversion seam. A non-well-formed value is rejected there before path or
  cache lookup; the independent string-based resolver/ESM graph APIs are not
  reinterpreted or widened by this parser-path checkpoint.
- Current readers retain same-major historical AST/IR inputs. Existing
  well-formed parser hashes and phase0 semantic artifacts remain unchanged;
  only schema identifiers, compatibility vectors, and IR-header snapshots
  advance.

## Post-Snapshot Update — Parser EOF Coordinate Schema (2026-07-17)

`bd-4tt6s` corrects the canonical `SyntaxTree` root span in both parser seams.
The root `end_column` is now the one-based UTF-8 byte column immediately after
the original source on its final physical line, rather than a hard-coded `1`.
This covers single-line sources, non-empty multiline tails, trailing LF/CRLF,
and exact byte widths for non-ASCII source text.

- The compatibility engine AST schema advances from v2 to v3; the native core
  AST schema advances independently from v3 to v4.
- The AST contract, serde shape, SHA-256 algorithm, and hash prefix are
  unchanged, so historical tree JSON remains readable. Historical v1/v2
  engine version vectors and pre-correction hashes remain pinned explicitly.
- Source-backed Parse Event IR materialization recognizes only the exact
  historical root-column defect, authenticated by its old tree hash; any other
  span or hash mismatch continues to fail closed.
- Parser-generated canonical hashes intentionally change when the old root
  column was wrong. The live phase0 fixture catalog and its content-addressed
  artifact bundle are regenerated under the new schema checkpoint.

## Post-Snapshot Update — `0.2.0` Compatibility Staging (2026-07-16)

`bd-n8eta.4.6` moves only `frankenengine-core` and `frankenengine-engine` to an unreleased `0.2.0` line. This is a source-compatibility boundary, not a tag or publication: unrelated workspace packages stay at `0.1.0`, and GA/release actions remain separately gated.

- Both public baseline-interpreter `Value` enums are now `#[non_exhaustive]`. Downstream matches must retain a fallback arm before the separately owned typed-Symbol runtime work appends a new variant.
- The downstream audit found 57 cross-crate match expressions across 13 files; every match already had a wildcard, binding, or equivalent fallback. `/data/projects/franken_node` had no direct construction, import, or match on either baseline `Value` type.
- Existing serde discriminants and payload bytes do not change. Focused historical-wire tests decode and re-encode all pre-migration variants byte-for-byte; the later Symbol children own any new wire values and execution-seed state.
- `IrSchemaVersion::CURRENT` remains `0.1.0` because this migration adds no IR opcode or persisted IR shape. The separately tracked `bd-f1ixz` must version its IR schema when its `CopyDataProperties` variants land on the unreleased `0.2.0` package line.

No `Value::Symbol`, typed executable property-key carrier, `symbol_state`, tag, or release is introduced here.

### Core exact quoted-string schema slice (`bd-vltnh`)

The subsequent core-first `bd-vltnh` slice advances
`frankenengine-core::ir_contract::IrSchemaVersion::CURRENT` to `0.2.0` and
the native core AST schema to `franken-engine.parser-ast.schema.v3`. Quoted
source literals, IR1 string literals, and the core IR3 constant pool now carry
exact `JsString` values, including lone UTF-16 surrogates. Historical
well-formed strings keep their prior leaf serde/canonical shape; exact values
use the tagged `$wtf16` unit representation. At that checkpoint the duplicated
`frankenengine-engine` parser/IR mirror still remained at its prior schema;
the engine section below records the subsequent mirror landing. Neither
checkpoint is a release.

### Engine exact quoted-string schema slice (`bd-vltnh`)

The engine mirror now advances `IrSchemaVersion::CURRENT` to `0.2.0` and its
live canonical AST schema to `franken-engine.parser-ast.schema.v2`. Quoted
expression literals cook directly into exact `JsString` code units, and that
carrier is preserved through the parser arena, AST serde/canonical values,
IR1 literals, IR3 constant-pool deduplication, and baseline `LoadStr`
execution. Ordinary well-formed strings retain their historical JSON and
canonical leaf shape; lone units use the tagged `$wtf16` representation and
remain distinct through an end-to-end source parse, lower, and execute cycle.

The later `bd-lfq44` checkpoint above completes exact module-specifier metadata
through the compiled parser/lowering path. Contextual legacy decimal escapes
remain tracked by `bd-xcqzp`. Neither schema landing creates a tag or release.

### Core `CopyDataProperties` IR schema slice (`bd-f1ixz`)

The core object-rest lane advances
`frankenengine-core::ir_contract::IrSchemaVersion::CURRENT` to `0.3.0` and
adds `Ir1Op::CopyDataProperties { excluded_count }` plus
`Ir3Instruction::CopyDataProperties { target, source, excluded, value_dst }`.
The `frankenengine-core` Cargo package remains on the deliberately unreleased
`0.2.0` compatibility-staging line; this is an IR wire revision, not a package
release or tag.

Existing IR variant names and payloads retain their prior serde and canonical
representations. Core `0.3.0` readers accept historical `0.2.0` headers, while
older readers reject the new externally tagged variants instead of silently
reinterpreting them. The downstream source audit found only the engine
differential oracle directly matching the core IR3 enum outside the core
crate, and both matches already have fallback arms; `/data/projects/franken_node`
has no direct imports, constructions, or matches of either core IR enum.

---

## Post-Snapshot Update — Claim-Evidence Integrity Capstone (2026-06-21)

The CEI epic (`bd-sde5e`, *stated state must be provably ≤ commit*) reached its capstone. Tracks A, C, E, F were already closed; this update lands Tracks **B** and **G** and the Track-H reflexive claim:

- **B.2 (`bd-sde5e.2.2`)** — every OBSERVED claim now carries a real `verification_result=passed` receipt from a live gate run (no backfill/pending). The last holdout, **FE-CLAIM-022** (cross-runtime lockstep oracle), is re-emitted from a live run against **real Node.js** (`/usr/bin/nodejs` v20.19.4) with zero divergences across node/bun/franken; the latent bench bug behind its old backfilled receipt (the FrankenEngine lane exhausting the containment instruction budget on the 10k/20k-iter workloads) is fixed by sizing the comparative workloads to `frankenctl run`'s real default budget. **FE-CLAIM-023** (cross-platform identical-hash reproducibility) is honestly downgraded `observed → target` — it is unprovable on a single host and its receipt was backfill/pending (precedent: FE-CLAIM-012). Result: the A.3 bidirectional audit is **27/27 sound (100%)**, `--blocking` exit 0.
- **B.4 (`bd-sde5e.2.4`)** — fresh-clone committed-evidence verification (`scripts/e2e/fresh_clone_evidence_verification_smoke.sh`) is 16/16 offline against a clean `git worktree` checkout.
- **G.1 (`bd-sde5e.7.1`)** — `scripts/run_claim_evidence_integrity_capstone.sh` composes the four CEI checks (claim-to-proof wording + A.1/A.3 bidirectional lattice, H.1 Merkle ledger, whole-document consistency, D.3 Test262 posture) into one fail-closed meta-gate, with an e2e replay wrapper and `docs/CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_RUNBOOK.md`.
- **G.3 (`bd-sde5e.7.3`)** — a no-mock acceptance drill (`scripts/e2e/claim_evidence_integrity_capstone_drift.sh`) injects an over-promotion of each class, asserts the capstone reddens the responsible sub-gate, and restores the tree byte-for-byte: the gate cannot be satisfied by fixtures.
- **H.2 (`bd-sde5e.8.2`)** — **FE-CLAIM-025** reflexive soundness claim (the gate gates itself), backed by the A.5 adversarial corpus (4/4) and committed in the H.1 Merkle ledger alongside the claims it checks. The pre-existing unbacked target FE-CLAIM-TEST262 was also given a git-tracked evidence bundle so the blocking audit is clean.

Honestly deferred (genuine environment blocks, not skipped work): **D.2** (`bd-sde5e.4.2`, full tc39/test262 corpus + denominator) and **H.4** (`bd-sde5e.8.4`, a *checked* Lean 4 theorem) remain open; D.2 needs the external corpus and H.4 needs a Lean toolchain absent on this host. Their parents (Tracks D, H) and the epic stay open accordingly. Relates to the honest GA-exit ledger (`bd-cixqu.47`).

Commits: `619479f2`, `163c17472`.

---

## Post-Snapshot Update — Track H Exception Semantics (2026-06-03)

- Promoted the README JavaScript surface coverage for `try` / `catch` / `finally` and `throw` / exception semantics to **Executed** after the Track H closure-capture work (`bd-cixqu.8.2`, `bd-cixqu.8.3`, `bd-cixqu.8.5`, `bd-cixqu.8.6`, `bd-cixqu.8.4`).
- Recorded try/catch/finally as a resolved parser and lowering inventory site, retaining `FE-PARSER-GAP-TRY-CATCH-0001` only as historical fail-closed provenance.
- Verified the exception semantics suite through `rch`: `cargo test -p frankenengine-engine --test exception_semantics_conformance` now covers 24 passing tests, including catch-binding closure capture and finally isolation.

---

## Version Timeline

`Kind` distinguishes a published release from a plain git tag.

| Version | Kind | Date | Summary |
|---------|------|------|---------|
| `main` @ [`b1f5bc91c`](https://github.com/Dicklesworthstone/franken_engine/commit/b1f5bc91c78e9c5fcec25aec11388a667ecd8ab8) | Unreleased `main` tip (not a tag, not a Release) | 2026-08-19 | Current window: crates.io sibling isolation, cell authority, RandomRead entropy, janitor docs-reorg. |
| `0.2.0` (unreleased) | `frankenengine-core` / `frankenengine-engine` Cargo versions | 2026-07-16 → present | Compatibility-staging line for public exhaustive-enum evolution; no tag or publication. |
| [`v0.1.0`](https://github.com/Dicklesworthstone/franken_engine/releases/tag/v0.1.0) | Published GitHub Release | 2026-05-29 | First conventional release and installed-binary baseline. The only GitHub Release in this repo. |
| [`backup/main-tip-1b2e6cf0`](https://github.com/Dicklesworthstone/franken_engine/tree/backup/main-tip-1b2e6cf0) | Backup tag (not a release) | 2026-04-16 | Mid-April main tip preserved during the Test262 / async-execution work. |
| [`backup/worktree-tip-1f288b45`](https://github.com/Dicklesworthstone/franken_engine/tree/backup/worktree-tip-1f288b45) | Backup tag (not a release) | 2026-03-18 | Mid-March worktree tip preserved during the integration-test enrichment wave. |

The four chronological capability waves below are research-grouped, not release-tagged.

### Per-Wave Metric Snapshot

Counts at each wave's closing commit, derived from `git ls-tree -r --name-only <wave-end-sha>` against the path patterns shown. Useful for "how much was built in this window?" without reading every commit. These are historical wave-end snapshots, not current-HEAD inventory counts.

| Surface | End of Wave 1 (2026-02-28) | End of Wave 2 (2026-03-31) | End of Wave 3 (2026-04-30) | End of Wave 4 (2026-05-15) |
|---|---:|---:|---:|---:|
| `crates/franken-engine/src/**/*.rs` (recursive) | 262 | 495 | 550 | 573 |
| `crates/franken-engine/tests/**/*.rs` (recursive) | 437 | 1,194 | 1,309 | 1,390 |
| `crates/franken-engine/tests/rgc_*.rs` (top level) | 0 | 34 | 36 | 37 |
| `scripts/run_*.sh` (top level only) | 118 | 201 | 227 | 241 |
| `.beads/issues.jsonl` entries | 951 | 1,118 | 1,739 | 2,584 |
| Commits added in the wave | ~315 | ~670 | ~2,115 | ~1,346 |

Read across rows for "growth per wave": notice Wave 2's near-doubling of the test surface (437 → 1,194) under the iterator-protocol + exception-epic landings, Wave 3's surge in beads (621 new entries, from 1,118 to 1,739) under the claim-to-proof matrix introduction, and Wave 4's continued bead growth (+845 to 2,584) tracking the IDEA-WIZARD series.

Two of the README's "Code Surface At A Glance" counts use top-level-only patterns (`src/*.rs` and `tests/*.rs`, not recursive), which gives slightly lower numbers than the recursive wave snapshots; the recursive figures above include `src/bin/`, `src/capability/`, `tests/_support/`, `tests/support/`, and `tests/conformance/`.

---

## Wave 1 — Bootstrap and scaffolding (2026-02-18 → 2026-02-28, ~315 commits)

The first ten days laid the entire repository skeleton: workspace structure, the canonical-encoding/IR/lowering/parser scaffolding, the original RGC ("Runtime Governance Compliance") gate framework, and the first wave of integration tests. The codebase grew from an empty repository to 262 source modules and 437 integration test files in this window (see the per-wave metric snapshot above).

### Delivered capability

- Cargo workspace with `franken-engine`, `franken-extension-host`, `franken-engine-test-support`, and `franken-metamorphic` crates plus an excluded in-progress `franken-core` extraction crate.
- Repository constitution: `AGENTS.md`, `docs/RUNTIME_CHARTER.md`, `docs/DONOR_EXTRACTION_SCOPE.md`, `docs/SEMANTIC_DONOR_SPEC.md` — the binding rules that pin "native-only Rust core execution", `#![forbid(unsafe_code)]`, the one-way `franken_node → franken_engine` dependency direction, and the claim-language policy that gates the whole project.
- Parser + AST + multi-stage lowering pipeline (IR0 raw → IR1 normalized → IR2 simplified → IR3 executable), the original baseline interpreter, the execution orchestrator, and the evidence ledger — i.e. the architecture documented in `docs/ARCHITECTURE_OVERVIEW.md`.
- First RGC gate framework: CI quality gates, artifact validator, runtime hotspot campaign, gate replay scripts, and the cross-track handoff protocol.
- 40+ "expand core modules" passes covering canonical encoding, compiler policy, conformance catalog, capability witness, capability framework, security epoch, replay scaffolding, signed manifest, evidence emission, and the first revocation chain primitives.
- First adversarial-testing surfaces: `adversarial_coevolution`, `counterfactual_replay`, `tail_risk`, `bifurcation`, `rollback_synthesis`, and the metamorphic-testing runner.
- FRX (FrankenReact eXtension) track charters and the first FRX lockstep oracle / counterfactual evaluator.

### Representative commits

- [`59a21498`](https://github.com/Dicklesworthstone/franken_engine/commit/59a21498) — `feat(engine): add RGC CI quality gates framework with tests, docs, and replay scripts`
- [`e308a853`](https://github.com/Dicklesworthstone/franken_engine/commit/e308a853) — `feat(engine): expand 40+ core modules with full runtime security, proof, and governance implementations`
- [`bd264466`](https://github.com/Dicklesworthstone/franken_engine/commit/bd264466) — `feat(engine): expand 8 core modules with canonical encoding, compiler policy, conformance catalog, etc.`
- [`f619b13b`](https://github.com/Dicklesworthstone/franken_engine/commit/f619b13b) — `test(engine): comprehensive integration test suite — 110 new test files`
- [`639d8928`](https://github.com/Dicklesworthstone/franken_engine/commit/639d8928) — `feat(engine): milestone evidence gates, demo-claim linkage, flake quarantine, and swarm control loop`
- [`4e344549`](https://github.com/Dicklesworthstone/franken_engine/commit/4e344549) — `feat(engine): adversarial coevolution, counterfactual replay, tail-risk, bifurcation, and rollback synthesis modules`
- [`fe44b2a3`](https://github.com/Dicklesworthstone/franken_engine/commit/fe44b2a3) — `feat(engine): metamorphic testing suite — seed transcript logging + runner enhancements`
- [`dd2162d8`](https://github.com/Dicklesworthstone/franken_engine/commit/dd2162d8) — `feat(engine): add static semantics, TS module resolution, and RGC coordination modules`
- [`02c47a89`](https://github.com/Dicklesworthstone/franken_engine/commit/02c47a89) — `feat(engine): add RGC-063 cross-platform matrix verification contract`
- [`d99aec56`](https://github.com/Dicklesworthstone/franken_engine/commit/d99aec56) — `feat(engine): enrich EvalError with correlation IDs, source locations, and stack frames`

---

## Wave 2 — Runtime semantics maturation (2026-03-01 → 2026-03-31, ~670 commits)

March was dominated by closing real JavaScript semantic gaps in the IR/runtime: the iterator protocol, exception/try/catch/finally lowering, generator/promise/spread semantics, ESM/CJS export resolution, module compatibility matrices, and a sweeping integration-test enrichment pass (the in-tree `memory/enrichment_sessions.md` records over 7,000 new tests landed in this window). It is also when the parser front-end picked up most of its ES2020 grammar surface and when the deterministic-hashing/length-prefixing audit hit most subsystems.

### Delivered capability

- **Iterator protocol** end-to-end: `iterator_protocol.rs` core substrate, 5 new IR1 opcodes (`ForInInit`, `ForInNext`, `ForOfInit`, `ForOfNext`, `IteratorClose`), real `for..in` / `for..of` lowering replacing the previous `UnsupportedSyntax` placeholders, and a 43-test `iterable_workload_verification` integration suite.
- **Exception epic** (RGC-313): IR lowering for `throw` / `try` / `catch` / `finally` (extended `BeginTry`, added `EnterFinally` / `EndFinally`), a real runtime unwinder (`CatchFrame`, `FinallyMode`, `pending_exception`, real dispatch), `rejection_reason_description` in module rejection, and 13 exception-semantics conformance tests.
- **Generator + promise + spread** semantics (RC beads 1.4, 1.12, 2.1).
- **IR3 instruction expansion**: 19 new variants (`Mod`, `Exp`, `Lt`, `Lte`, `Gt`, `Gte`, `Eq`, `StrictEq`, `NotEq`, `StrictNotEq`, `BitAnd`, `BitOr`, `BitXor`, `Shl`, `Shr`, `Ushr`, `InstanceOf`, `InOp`, `Construct`) with matching baseline-interpreter dispatch and execution-orchestrator mnemonics.
- **ESM/CJS interop**: overhauled ES2020 star re-export semantics, conditional and external `exports` map resolution, scoped-package and extensionless-relative tests, Node-compat CJS→ESM specimens, and a hybrid lane router; the module compatibility matrix gate gained npm-style `pkg.js` / `@scope/pkg.js` extension-probe anchoring with fail-closed `package.json type=module` behavior in native/node_compat modes.
- **Parser frontier (March-landed work only)**: initial tagged-template support and template-interpolation hardening, fail-closed handling for `super` / `new.target` / `import.meta`, named-export-clause validation, and the parser-oracle / parser-frontier-harness gates. (Earlier `parser arena VariableDeclaration` and named/namespace imports landed in Wave 1; tagged-template-as-Call, trailing-line-comment stripping, named-declaration export desugaring, simd_lexer content-binding, and the parallel scoped-worker lex all land later — see Waves 3 and 4.)
- **Cross-repo integration suite** (`scripts/run_cross_repo_integration_suite.sh`) and machine-readable contract (`docs/cross_repo_integration_suite_v1.json`) for `/dp/asupersync`, `/dp/frankentui`, `/dp/frankensqlite` boundaries.
- **Deterministic-hashing audit**: length-prefixing applied across content hashes (gate results, evidence bundles, signed manifests, rewrite packs, IFC declassification authorization, supremacy verdict aggregation, etc.) so concatenation collisions are no longer possible.
- **frankenctl CLI** gained `help <command>` navigation, rch-wrapped replay command emission in artifact bundles, observability_mode JSON output and hash-stability regression tests, and preserved-bundle replay support across multiple gates.
- **Cache-oblivious metadata substrate**, kernelized shift guard, semantic dark-matter engine (RGC-617), and the rough-path regime geometry orchestrator landed as performance/observability infrastructure.

### Representative commits

- [`8753c439`](https://github.com/Dicklesworthstone/franken_engine/commit/8753c439) — `feat(engine): module system — async evaluation dependency tracking and compatibility matrix validation`
- [`f10150a2`](https://github.com/Dicklesworthstone/franken_engine/commit/f10150a2) — `feat(engine): overhaul ESM export resolution to match ES2020 star re-export semantics`
- [`b17332ea`](https://github.com/Dicklesworthstone/franken_engine/commit/b17332ea) — `feat(engine): conditional exports map resolution tests for module resolver and compatibility matrix`
- [`74a976ab`](https://github.com/Dicklesworthstone/franken_engine/commit/74a976ab) — `test(resolver): add scoped-package and extensionless-relative integration tests across compatibility modes`
- [`44e1e65b`](https://github.com/Dicklesworthstone/franken_engine/commit/44e1e65b) — `feat(engine): add cache-oblivious metadata substrate, kernelized shift guard, and semantic dark-matter engine`
- [`d7e1af52`](https://github.com/Dicklesworthstone/franken_engine/commit/d7e1af52) — `feat(engine): add rough-path regime geometry orchestrator (RGC-617)`
- [`bb8cb07f`](https://github.com/Dicklesworthstone/franken_engine/commit/bb8cb07f) — `feat(engine): cross-repo integration suite for multi-project contract verification`
- [`135a1c2c`](https://github.com/Dicklesworthstone/franken_engine/commit/135a1c2c) — `feat(rgc): add CI gate verdict, failure routing matrix, lane repro index, and health summary artifacts`
- [`1bf264a8`](https://github.com/Dicklesworthstone/franken_engine/commit/1bf264a8) — `feat(engine): versioned rewrite pack — canonical pair keys, cost model guards, and pack diff`
- [`e8ed383c`](https://github.com/Dicklesworthstone/franken_engine/commit/e8ed383c) — `fix(engine): deterministic content hashing — length-prefix fields and sort collections before computing digests`
- [`215daf38`](https://github.com/Dicklesworthstone/franken_engine/commit/215daf38) — `fix(engine): seqlock fastpath — panic safety via SequencePublishGuard and poison recovery`

---

## Wave 3 — Real-execution conformance and benchmark truth (2026-04-01 → 2026-04-30, ~2,115 commits)

April was the most intense month by commit count and pivoted the project from "self-consistent infrastructure" to "real-execution truth". Test262 stopped using fake fixtures and started running real JavaScript; the benchmark harness stopped using hardcoded baselines and started measuring child wall-time and peak RSS via Linux `pidfd`+`wait4`; the claim-to-proof matrix v1 was introduced as the binding gate over every README claim; and the first set of "live" guardplane/IFC/quarantine examples replaced their mock counterparts.

### Delivered capability

- **Claim-to-proof matrix v1** (`docs/claim_to_proof_matrix_v1.json`, `docs/CLAIM_TO_PROOF_MATRIX_V1.md`) wired into both `scripts/run_claim_to_proof_matrix_gate.sh` and the README. All 21 tracked claims classified as `observed` / `target` / `hypothesis`; the gate refuses progression when actual wording is stronger than the allowed state. `bd-csnqb` swept the unsupported "formal mathematical" claims and downgraded them in-tree.
- **Real Test262 harness**: replaced fake test data and hardcoded fake results with actual JavaScript execution in the release gate; arrow-function output-mismatch regression closed; frontmatter parser hardened against overlapping markers; iterator-conformance comparison now uses the shared eval-vs-expected helper.
- **Real benchmark measurement**: `benchmark-e2e` switched from `timeout(1)` shell wrapping to in-process timeout + threaded stdio capture, then to memfd-based stderr capture with OnceLock host-facts cache and typed artifact serializers; child wall-time and peak RSS measured via Linux pidfd+wait4 with stderr timing-footer portability fallback; live Node/Bun baseline measurement (`bd-16ch6`); hardcoded throughput baselines eliminated (`bd-1pq04`); fake containment-latency data eliminated (`bd-69kbi`); cross-runtime output equivalence proved from captured bytes.
- **Real interpreter semantics**: Array.from(iterable, mapFn, thisArg); Generator/Async/AsyncGenerator dispatch; Function.{call,apply}; reduceRight; Map/Set/WeakMap/WeakSet seeded from iterables; Promise.all delegated to combinator; async function execution semantics (`bd-2lg6f`); receiver-aware builtin dispatch with real `Array.some` callback; full function-body try/catch/finally + JumpIfFalsy two-target lowering + EnterCatch label binding; IR3-aware eval completion; IR3 TemplateLiteral emission; SharedBudgetEnforcer so subsystems observe live certificate updates; GovernanceContext composition root (`bd-2hzkh`).
- **Parser front-end finalization**: tagged-template expressions parsed as Call with template-literal argument; trailing line comments stripped and unseparated expression sequences rejected; named-declaration exports desugared into declaration + named clause; same-line statements after `export function` / `export class` blocks split correctly; `simd_lexer` token witnesses mix input hashes so token outputs are content-bound.
- **Live "impossible-by-default" examples**: live guardplane posterior + expected-loss decision example; live quarantine propagation with convergence evidence; live IFC/declassification example with signed receipts (`bd-dpfvh`); live capability rejection example (`bd-1bao8`); `production_feature_catalog` gate companion; `bench-vs-node` example (`bd-79rwx`); certified rewrite optimization demo; react compile demo (`bd-3eydu`); decision-receipt demo. All 13 "impossible-by-default" capabilities now have demo directories (one without a dedicated directory; see `examples/README.md`).
- **Proof-artifact contract** (`proof-artifact` module): shared manifest module + script helper; adopted across three existing gates; events.jsonl race condition fixed with atomic emission; enumeration validation with Ord trait; cryptographic content binding added to IFC system.
- **Red-team / attacker harness** (`bd-28otw`): attacker execution harness with explicit scenario outcomes replacing hardcoded baseline assumptions; comprehensive baseline validation in compromise-rate gate.
- **Fuzzing**: parser fuzz harness, proof-artifact JSON validation targets (PHASE 3), shadow_panel_bundle target (`bd-hbil1`), ts_module_resolution_resolve target (`bd-6fcpn`), parallel-parser coverage-guided fuzz harness.
- **Shadow daemon adoption gates + mutation policy enforcement** — preserved the advisory-only mode invariant documented in `docs/SHADOW_DAEMON_PROOF_STATE.md`.
- **Privacy verification artifacts**, declassification timestamp bounds, replay coverage proof metric gate (`bd-2488a`), throughput disruptive-floor metric gate with Node/Bun denominators, three new metric gates and one proof example (`bd-38mby`, `bd-1qr4f`, `bd-3mp80`).
- **frankenctl** `run` subcommand expanded with structured output + capability flags; `--observability-mode` consistently surfaced in JSON; the README CLI smoke workflow (`scripts/e2e/readme_cli_workflow_smoke.sh`) was wired to the shared proof contract (`bd-1fjqa`).
- **GA exit evidence package**, cross-architecture reproducibility contract, deterministic support-bundle export, workload preflight doctor workflow, deterministic technical-report renderer, rollout-controller guardrails, replication claim tracker, acceptance ledger.

### Representative commits

- [`afe84382`](https://github.com/Dicklesworthstone/franken_engine/commit/afe84382) — `feat(claim-matrix): seed claim-to-proof matrix v1 + wire into gates and README`
- [`71cda5e5`](https://github.com/Dicklesworthstone/franken_engine/commit/71cda5e5) — `feat(claim-matrix): add gate runner script + tighten must_contain anchors`
- [`e84796f1`](https://github.com/Dicklesworthstone/franken_engine/commit/e84796f1) — `feat(bd-csnqb): audit and downgrade unsupported formal mathematical claims`
- [`d21262af`](https://github.com/Dicklesworthstone/franken_engine/commit/d21262af) — `feat(test262): implement real Test262 conformance harness integration`
- [`21b485a0`](https://github.com/Dicklesworthstone/franken_engine/commit/21b485a0) — `feat(test262): replace fake test data with real JavaScript execution in release gate`
- [`d728d81a`](https://github.com/Dicklesworthstone/franken_engine/commit/d728d81a) — `feat(benchmark-e2e): measure child wall-time and peak RSS via Linux pidfd+wait4 with in-band stderr timing footer fallback`
- [`38cfc002`](https://github.com/Dicklesworthstone/franken_engine/commit/38cfc002) — `feat(benchmark-e2e): memfd-based stderr capture, OnceLock host-facts cache, runtime launch resolution, and typed artifact serializers`
- [`f5847faa`](https://github.com/Dicklesworthstone/franken_engine/commit/f5847faa) — `feat(bd-16ch6): implement live Node/Bun baseline measurement for throughput gate`
- [`30f3aa96`](https://github.com/Dicklesworthstone/franken_engine/commit/30f3aa96) — `feat(bd-1pq04): eliminate hardcoded throughput baselines and add defensive validation`
- [`4b2c2b03`](https://github.com/Dicklesworthstone/franken_engine/commit/4b2c2b03) — `feat(bd-69kbi): eliminate fake containment latency data and add defensive validation`
- [`d2ea4d17`](https://github.com/Dicklesworthstone/franken_engine/commit/d2ea4d17) — `feat(examples): implement bd-dpfvh live IFC/declassification example`
- [`ab686dfa`](https://github.com/Dicklesworthstone/franken_engine/commit/ab686dfa) — `feat(proof): Live quarantine propagation example with convergence evidence`
- [`267095c8`](https://github.com/Dicklesworthstone/franken_engine/commit/267095c8) — `feat(examples): implement bd-1bao8 live capability rejection example`
- [`029e9454`](https://github.com/Dicklesworthstone/franken_engine/commit/029e9454) — `feat(proof): Live guardplane posterior and expected-loss decision example`
- [`242bf0b5`](https://github.com/Dicklesworthstone/franken_engine/commit/242bf0b5) — `feat(replay): add replay coverage proof metric gate (bd-2488a)`
- [`8086b135`](https://github.com/Dicklesworthstone/franken_engine/commit/8086b135) — `feat(metrics): Implement throughput disruptive-floor metric gate with Node/Bun denominators`
- [`9e3576b1`](https://github.com/Dicklesworthstone/franken_engine/commit/9e3576b1) — `feat(metrics): implement bd-1vwza compromise rate metric gate`
- [`aa11e88c`](https://github.com/Dicklesworthstone/franken_engine/commit/aa11e88c) — `feat(baseline-interpreter): add Generator/Async/AsyncGenerator dispatch + Function.{call,apply} + reduceRight`
- [`5a3d047a`](https://github.com/Dicklesworthstone/franken_engine/commit/5a3d047a) — `feat(lowering): function-body try/catch/finally + JumpIfFalsy two-target lowering + EnterCatch label binding`
- [`d728d81a`](https://github.com/Dicklesworthstone/franken_engine/commit/d728d81a) — `feat(benchmark-e2e): wall-time and peak RSS via pidfd+wait4`
- [`39ded447`](https://github.com/Dicklesworthstone/franken_engine/commit/39ded447) — `feat(red-team): implement attacker execution harness (bd-28otw)`
- [`f76c92e9`](https://github.com/Dicklesworthstone/franken_engine/commit/f76c92e9) — `feat(fuzz): add parallel parser coverage-guided fuzz harness`
- [`8c5c9459`](https://github.com/Dicklesworthstone/franken_engine/commit/8c5c9459) — `feat(proof-artifact): Fix events.jsonl race condition with atomic emission`
- [`3cb9c7a8`](https://github.com/Dicklesworthstone/franken_engine/commit/3cb9c7a8) — `feat(governance): add GovernanceContext composition root (bd-2hzkh)`

---

## Wave 4 — Claim promotion, proof-specialized optimization, rch hardening (2026-05-01 → 2026-05-15, ~1,346 commits)

May has been about turning observed-but-fragile gates into hard contracts. The "idea-wizard" series (X, XI, XII, XIII) walked the README's remaining `hypothesis` claims toward `observed` by adding explicit proof bundles, rollback receipts, and no-mock acceptance drills. Concurrently, the `rch` (remote compilation hooks) infrastructure was hardened against worker drift, shard pressure, and brownouts so the large-batch agent swarms could keep landing work. The `franken-core` extraction crate started executing real class semantics for the first time.

### Delivered capability

- **`franken-core` extracted runtime modules** finally land in a compileable form (`bd-zsais`); class semantics start executing for real — class-expression semantics, `extends`/`super` dispatch, `new.target` in constructors, accessor getter/setter descriptor invocation via `GetProperty`/`SetProperty`, baseline-interpreter execution of class accessor get/set descriptors, private-accessor-key prefix tagging during lowering, heap-backed own-property storage for callable values + class-lowering Pop fix.
- **Async generators**: `.next()` body execution implemented; async function execution semantics finished (`bd-mw20e.2`); pending-await contract made explicit (`bd-jcqqj` follow-up); await IFC labels preserved (`bd-jcqqj`).
- **Proof-specialized optimization promotion control loop** (IDEA-WIZARD-XI, parent `bd-xg3d6`): promotion-control contract & inventory (`bd-sisok`), deterministic promotion eligibility composer (`bd-4j2ck`), demotion rollback and safe-mode replay receipts (`bd-or2e1`), workload-regime transfer guard for promotion decisions (`bd-jp4r0`), promotion-state surfacing in operator runbook/status (`bd-yo0eh`), no-mock promotion-control replay drill and truth gate (`bd-xbesa`).
- **Real hot-path proof** (IDEA-WIZARD-X, `bd-t5k40`): rejected simulated hot-path evidence; rch hot-path wrapper (`scripts/run_real_hot_path_proof.sh smoke`); hot-path evidence runbook (`docs/REAL_HOT_PATH_EVIDENCE_RUNBOOK.md`); hot-path contract goldens; hot-path evidence drill. `FE-CLAIM-010` (Node/Bun denominator) explicitly kept `target` until live denominator artifacts replace placeholders; `MockCertificate` and `hot_paths_simulation` artifacts now rejected as backing evidence.
- **Zero-ready validation truth lane** (IDEA-WIZARD-XII, `bd-n51l8`): rch policy gate is now wrapper-aware (`bd-n51l8.1`); closed-bead semantic contradiction scanner (`bd-n51l8.2`); reopen real pending-promise await execution from source evidence (`bd-n51l8.3`); zero-ready source-gap picker for bounded follow-up beads (`bd-n51l8.4`); zero-ready truth surfaced in operator handoff status (`bd-n51l8.5`); no-mock drill for the lane (`bd-n51l8.6`).
- **README hypothesis-claim promotion** (IDEA-WIZARD-XIII, `bd-ly6hp`): claim-promotion contract for hypothesis gaps (`.1`); transparency-log decision receipt proof bundle (`.2`); live quarantine mesh convergence proof (`.3`); capability-typed ambient-authority rejection pilot (`.4`); README claim promotion gated on live proof artifacts (`.5`); no-mock claim-promotion acceptance drill (`.6`); explicit rollback-evidence requirement in the promotion gate runner (`bd-zso7f`).
- **rch (remote compilation hooks) brownout/preflight hardening**: worker-pressure preflight is now default; rejection of expected/native/selected worker drift; route preference propagation; preserved worker status on route drift; fail-closed lib-unit smoke execution; rch policy-gate awareness of wrapper cargo gates; shard pressure preflight contract; fail-closed shard runner; shard-runner termination classification; opt-in shard keepalive instrumentation; brownout source closeout + validation baseline documentation.
- **Parser & lexer**: parallel lex chunks execute on scoped workers; continued logical-line indentation normalization; debug-derive for scoped chunk lex; trailing line-comment stripping; same-line statement splitting after export blocks.
- **Re-enabled `certified_rewrite_optimizer`** (`3f046a2a`): aligned with current APIs after a long pause.
- **Shell hygiene smoke gate** (`bd-j2o4x`): matrix coverage of operator and e2e scripts.
- **Topology queue admission decisions**, removal of placeholder authenticity-signature seeds, hardening of `proof_release_gate` (requires `cas://` URIs to embed archive_root hex prefix), and continued length-prefixing pass across remaining hash inputs (conformance harness failure-id, repro-digest, React package cohort, hole witness generator, hardware parameter manifold, AOT entrygraph compiler, GovernanceReport schema/spec, support-bundle evidence, GateResult variable-length fields).

### Closed workstreams (selected)

- `bd-xg3d6` (IDEA-WIZARD-XI parent) — Proof-specialized optimization promotion control loop
- `bd-ly6hp` (IDEA-WIZARD-XIII parent) — Promote README hypothesis claims with live proof bundles (parent open at time of writing; children `.1`–`.6` closed in sequence)
- `bd-n51l8` (IDEA-WIZARD-XII parent) — Zero-ready validation truth and semantic debt control plane
- `bd-t5k40` (IDEA-WIZARD-X) — Replace simulated hot-path evidence with real runtime proof lanes
- `bd-2488a` — Replay coverage proof metric gate
- `bd-1vwza` — Compromise rate metric gate
- `bd-38mby` / `bd-1qr4f` / `bd-3mp80` — Three named metric gates landed with proof examples
- `bd-zso7f` — Explicit rollback evidence requirement in promotion gate runner

### Representative commits

- [`f925fcf5`](https://github.com/Dicklesworthstone/franken_engine/commit/f925fcf5) — `feat(proof): add optimization promotion contract`
- [`511f02a1`](https://github.com/Dicklesworthstone/franken_engine/commit/511f02a1) — `feat(proof): add optimization promotion composer`
- [`ecb397fe`](https://github.com/Dicklesworthstone/franken_engine/commit/ecb397fe) — `feat(proof): add optimization demotion receipts`
- [`c695936d`](https://github.com/Dicklesworthstone/franken_engine/commit/c695936d) — `feat(proof): add optimization transfer guard`
- [`df1f3121`](https://github.com/Dicklesworthstone/franken_engine/commit/df1f3121) — `feat(proof): add optimization operator status`
- [`42428d68`](https://github.com/Dicklesworthstone/franken_engine/commit/42428d68) — `feat(proof): add optimization replay drill`
- [`636d7f11`](https://github.com/Dicklesworthstone/franken_engine/commit/636d7f11) — `feat(proof): add rch hot path wrapper`
- [`31798477`](https://github.com/Dicklesworthstone/franken_engine/commit/31798477) — `test(claims): reject simulated hot path evidence`
- [`f4b0e27c`](https://github.com/Dicklesworthstone/franken_engine/commit/f4b0e27c) — `docs(proof): publish hot path evidence runbook`
- [`177ddc52`](https://github.com/Dicklesworthstone/franken_engine/commit/177ddc52) — `test: add quarantine mesh proof wrapper`
- [`c4c350f6`](https://github.com/Dicklesworthstone/franken_engine/commit/c4c350f6) — `test: add transparency receipt proof bundle`
- [`ab19aa69`](https://github.com/Dicklesworthstone/franken_engine/commit/ab19aa69) — `test: add capability typed authority proof`
- [`8c6a4038`](https://github.com/Dicklesworthstone/franken_engine/commit/8c6a4038) — `test: add claim promotion contract gate`
- [`6b004fdc`](https://github.com/Dicklesworthstone/franken_engine/commit/6b004fdc) — `test: gate xiii claim promotion reports`
- [`2b7886de`](https://github.com/Dicklesworthstone/franken_engine/commit/2b7886de) — `test: add xiii claim promotion acceptance drill`
- [`d37aa248`](https://github.com/Dicklesworthstone/franken_engine/commit/d37aa248) — `fix: require promotion rollback evidence`
- [`d51f2715`](https://github.com/Dicklesworthstone/franken_engine/commit/d51f2715) — `test: add shell hygiene smoke gate`
- [`32574c81`](https://github.com/Dicklesworthstone/franken_engine/commit/32574c81) — `feat(baseline-interpreter): implement async function execution semantics (bd-mw20e.2)`
- [`9611a028`](https://github.com/Dicklesworthstone/franken_engine/commit/9611a028) — `feat(async-generators): implement async generator .next() body execution`
- [`3f046a2a`](https://github.com/Dicklesworthstone/franken_engine/commit/3f046a2a) — `feat(franken-engine): re-enable certified_rewrite_optimizer module and align with current APIs`
- [`9512282b`](https://github.com/Dicklesworthstone/franken_engine/commit/9512282b) — `feat(franken-core): land the five extracted runtime modules to make standalone manifest compileable (bd-zsais)`
- [`d35c9758`](https://github.com/Dicklesworthstone/franken_engine/commit/d35c9758) — `feat(franken-core): execute class extends super dispatch`
- [`7af839bc`](https://github.com/Dicklesworthstone/franken_engine/commit/7af839bc) — `feat(franken-core): execute new.target in constructors`
- [`b5d4aae6`](https://github.com/Dicklesworthstone/franken_engine/commit/b5d4aae6) — `feat(parser): execute parallel lex chunks on scoped workers`
- [`7a16247f`](https://github.com/Dicklesworthstone/franken_engine/commit/7a16247f) — `feat(rch): add shard pressure preflight contract`
- [`bc84e2cf`](https://github.com/Dicklesworthstone/franken_engine/commit/bc84e2cf) — `feat(rch): add fail-closed shard runner`
- [`b696d496`](https://github.com/Dicklesworthstone/franken_engine/commit/b696d496) — `feat(audit): objective artifact completion audit gate (new contract)`

---

## Cross-cutting workstreams

These are visible across all four waves and worth tracking separately from any single month.

### Beads as the unit of work

The project uses `br` (the Rust-port `beads_rust` tracker) with issues checked into `.beads/issues.jsonl`. The README's claim-language gate (`docs/CLAIM_TO_PROOF_MATRIX_V1.md`) names a specific owning bead for every tracked claim. The IDEA-WIZARD-* series above each correspond to a parent bead with `.A`–`.F` children; the same shape recurs across earlier RGC-* epics.

### Always-on gates layered onto every change

`scripts/` ships 241 `run_*.sh` files. Major families:

- `run_rgc_*` — Runtime Governance Compliance (56 scripts: cross-platform matrix, security enforcement, runtime semantics, statistical validation, performance regression, JSON compound traversal, NPM compatibility matrix, observability publication policy, module interop matrix, CLI operator workflow, docs/help surface audit, zero-placeholder, etc.)
- `run_parser_*` — Parser (36 scripts: oracle, phase0 artifact, performance promotion, frontier harness, operator runbook, gap inventory)
- `run_frx_*` — FrankenReact/FRX (34 scripts: canonical React corpus, SSR/hydration/RSC, local semantic atlas, Track D WASM lane, Track E verification/fuzz, online regret + change-point demotion controller)
- `run_claim_to_proof_matrix_gate.sh`, `run_real_hot_path_proof.sh`, `run_reproducibility_contract_suite.sh`, `run_metamorphic_suite.sh` and other top-level claim/evidence gates.

Every gate has a matching `scripts/e2e/*_replay.sh` wrapper that can replay the latest preserved artifact bundle or a pinned timestamp under `artifacts/`.

### Determinism and length-prefixed hashing

A repeating motif across all four waves: any time a content hash mixes variable-length data, the change replaces concatenation with length-prefixing so that distinct field decompositions cannot collide. Examples appear in February (initial scaffolding), March (rewrite packs, support bundles), April (proof-artifact contract), and May (GateResult variable-length fields, AOT entrygraph hashing, conformance-harness failure-ids).

### Sibling-repo reuse contract

Per `docs/RUNTIME_CHARTER.md` §5, `franken_engine` consumes (one-way): `/dp/asupersync` (control plane), `/dp/frankentui` (TUI), `/dp/frankensqlite` (persistence; with the documented `DEVIATION` for typed-heavy stores still routing through generic `storage_adapter.rs`), `/dp/sqlmodel_rust` (typed schema layers, partially adopted), `/dp/fastapi_rust` (service/API control surfaces). Cross-repo integration is verified by `scripts/run_cross_repo_integration_suite.sh` and pinned in `docs/cross_repo_integration_suite_v1.json`.

---

## Notes for Agents

- The version timeline is sparse on purpose: the only GitHub Release is [`v0.1.0`](https://github.com/Dicklesworthstone/franken_engine/releases/tag/v0.1.0) (2026-05-29). Cargo `0.2.0` is an unreleased compatibility-staging line, not a tag. To pick an "as-of" snapshot after that, use a commit SHA.
- The capability-wave sections are research-grouped by month because that's how the work actually landed; they are not release notes.
- For any claim made in `README.md`, the authoritative gate is `scripts/run_claim_to_proof_matrix_gate.sh ci` against `docs/claim_to_proof_matrix_v1.json`. If a README claim says something stronger than the matrix allows, the gate fails — the matrix wins.
- For implementation evidence behind any wave entry, follow the linked commit, then `git log -- <touched-files>` from that commit to see the surrounding cluster.
- For workstream intent, look up the bead id (`bd-xxxxx` or `bd-xxxxx.N`) with `br show <id>` or read `.beads/issues.jsonl` directly.
- Per-session enrichment notes (large test landings) are kept in `memory/enrichment_sessions.md`, `memory/completed_beads.md`, and the dated session files (`memory/session_*.md`). Treat those as frozen-in-time field notes, not current state.
- `legacy_v8/` and `legacy_quickjs/` are reference corpora only; the runtime charter forbids them from becoming runtime dependencies.
