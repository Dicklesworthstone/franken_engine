# Changelog

This is a synthesized, agent-facing changelog for the full history of `franken_engine`.

Scope window: project inception on 2026-02-18 through current `main` (`d51f2715`, 2026-05-15).

This document was rebuilt from git history (4,446 commits, no published releases), the checked-in beads tracker (`.beads/issues.jsonl`), the in-tree `docs/CLAIM_TO_PROOF_MATRIX_V1.md` claim ledger, and the contemporaneous workstream notes left in `docs/` and `runbooks/`.

The project ships a single `0.1.0` Cargo manifest across the workspace and has no GitHub Releases or version tags — only two backup tags (`backup/main-tip-1b2e6cf0`, `backup/worktree-tip-1f288b45`). All published evidence is artifact-bundle based; the "version" of any given decision/benchmark/replay claim is its artifact manifest and its bead, not a release number.

---

## Version Timeline

`Kind` distinguishes a published release from a plain git tag.

| Version | Kind | Date | Summary |
|---------|------|------|---------|
| `0.1.0` (in-development) | Cargo workspace version | 2026-02-18 → present | Continuous `main`-only development; no tagged releases. Evidence ships per artifact bundle, not per version. |
| [`backup/main-tip-1b2e6cf0`](https://github.com/Dicklesworthstone/franken_engine/tree/backup/main-tip-1b2e6cf0) | Backup tag (not a release) | 2026-04-16 | Mid-April main tip preserved during the Test262 / async-execution work. |
| [`backup/worktree-tip-1f288b45`](https://github.com/Dicklesworthstone/franken_engine/tree/backup/worktree-tip-1f288b45) | Backup tag (not a release) | 2026-03-18 | Mid-March worktree tip preserved during the integration-test enrichment wave. |

The four chronological capability waves below are research-grouped, not release-tagged.

### Per-Wave Metric Snapshot

Counts at each wave's closing commit (`git ls-tree -r --name-only <sha>`-derived). Useful for "how much was built in this window?" without reading every commit. The HEAD column shows current state (some Wave-4 modules have since been consolidated/renamed).

| Surface | End of Wave 1 (2026-02-28) | End of Wave 2 (2026-03-31) | End of Wave 3 (2026-04-30) | End of Wave 4 (2026-05-15) | HEAD |
|---|---:|---:|---:|---:|---:|
| `crates/franken-engine/src/*.rs` | 262 | 495 | 550 | 573 | 511 |
| `crates/franken-engine/tests/*.rs` | 437 | 1,194 | 1,309 | 1,390 | 1,382 |
| `crates/franken-engine/tests/rgc_*.rs` | 0 | 34 | 36 | 37 | 37 |
| `scripts/run_*.sh` | 118 | 201 | 227 | 241 | 241 |
| `.beads/issues.jsonl` entries | 951 | 1,118 | 1,739 | 2,584 | 2,584 |
| Commits added in the wave | ~315 | ~670 | ~2,115 | ~1,346 | n/a |

Read across rows for "growth per wave": notice Wave 2's near-doubling of the test surface (437 → 1,194) under the iterator-protocol + exception-epic landings, Wave 3's surge in beads (621 new entries, from 1,118 to 1,739) under the claim-to-proof matrix introduction, and Wave 4's continued bead growth (+845 to 2,584) tracking the IDEA-WIZARD series.

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

- `run_rgc_*` — Runtime Governance Compliance (~55 scripts: cross-platform matrix, security enforcement, runtime semantics, statistical validation, performance regression, JSON compound traversal, NPM compatibility matrix, observability publication policy, module interop matrix, CLI operator workflow, docs/help surface audit, zero-placeholder, etc.)
- `run_parser_*` — Parser (~32: oracle, phase0 artifact, performance promotion, frontier harness, operator runbook, gap inventory)
- `run_frx_*` — FrankenReact/FRX (~32: canonical React corpus, SSR/hydration/RSC, local semantic atlas, Track D WASM lane, Track E verification/fuzz, online regret + change-point demotion controller)
- `run_claim_to_proof_matrix_gate.sh`, `run_real_hot_path_proof.sh`, `run_reproducibility_contract_gate.sh`, `run_metamorphic_testing.sh` and other top-level claim/evidence gates.

Every gate has a matching `scripts/e2e/*_replay.sh` wrapper that can replay the latest preserved artifact bundle or a pinned timestamp under `artifacts/`.

### Determinism and length-prefixed hashing

A repeating motif across all four waves: any time a content hash mixes variable-length data, the change replaces concatenation with length-prefixing so that distinct field decompositions cannot collide. Examples appear in February (initial scaffolding), March (rewrite packs, support bundles), April (proof-artifact contract), and May (GateResult variable-length fields, AOT entrygraph hashing, conformance-harness failure-ids).

### Sibling-repo reuse contract

Per `docs/RUNTIME_CHARTER.md` §5, `franken_engine` consumes (one-way): `/dp/asupersync` (control plane), `/dp/frankentui` (TUI), `/dp/frankensqlite` (persistence; with the documented `DEVIATION` for typed-heavy stores still routing through generic `storage_adapter.rs`), `/dp/sqlmodel_rust` (typed schema layers, partially adopted), `/dp/fastapi_rust` (service/API control surfaces). Cross-repo integration is verified by `scripts/run_cross_repo_integration_suite.sh` and pinned in `docs/cross_repo_integration_suite_v1.json`.

---

## Notes for Agents

- The version timeline is intentionally sparse: this repo has no released versions. To pick a "as-of" snapshot, use a commit SHA, not a tag.
- The capability-wave sections are research-grouped by month because that's how the work actually landed; they are not release notes.
- For any claim made in `README.md`, the authoritative gate is `scripts/run_claim_to_proof_matrix_gate.sh ci` against `docs/claim_to_proof_matrix_v1.json`. If a README claim says something stronger than the matrix allows, the gate fails — the matrix wins.
- For implementation evidence behind any wave entry, follow the linked commit, then `git log -- <touched-files>` from that commit to see the surrounding cluster.
- For workstream intent, look up the bead id (`bd-xxxxx` or `bd-xxxxx.N`) with `br show <id>` or read `.beads/issues.jsonl` directly.
- Per-session enrichment notes (large test landings) are kept in `memory/enrichment_sessions.md`, `memory/completed_beads.md`, and the dated session files (`memory/session_*.md`). Treat those as frozen-in-time field notes, not current state.
- `legacy_v8/` and `legacy_quickjs/` are reference corpora only; the runtime charter forbids them from becoming runtime dependencies.
