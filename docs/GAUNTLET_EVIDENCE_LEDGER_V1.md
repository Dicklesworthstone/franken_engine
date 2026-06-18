# FrankenEngine Gauntlet Evidence Ledger V1

## Purpose

This ledger records the current result of applying the rust-port gauntlet
methodology to FrankenEngine in greenfield-runtime mode. It is not a release
promotion document and it does not strengthen any claim in the claim-to-proof
matrix. Its job is to keep architecture understanding, negative evidence,
correctness/conformance/parity gates, and performance optimization candidates
in one auditable place.

Current run date: 2026-06-18.

## Source-of-Truth Inputs

| Input | Current role |
| --- | --- |
| `AGENTS.md` | Repo operating constraints: no file deletion, no destructive git, Cargo-only Rust 2024, `main` branch, `rch` for heavy Cargo validation, and explicit post-change gates. |
| `README.md` | Public claim language, architecture narrative, run/test/benchmark workflow, and OBSERVED/TARGET/HYPOTHESIS wording discipline. |
| `docs/CLAIM_TO_PROOF_MATRIX_V1.md` | Human companion to `docs/claim_to_proof_matrix_v1.json`; authoritative state is the JSON matrix. |
| `docs/PERFORMANCE_BASELINE.md` | Performance acceptance standard and H1/H4/H6-era baseline evidence summary. |
| `docs/operator-gates/FE_CLAIM_010_PROMOTION_DECISION.md` | Current Node/Bun denominator promotion decision for FE-CLAIM-010. |
| `docs/E8_ANALYZED_SUBSET_REFUSAL_LEDGER.md` | E8 refusal vocabulary and capstone contract for negative non-use evidence. |
| `tests/artifacts/perf/20260520T214829Z-prof-pass1/` | Frozen perf pass1 profile and Criterion estimates used by H1 validation. |
| `docs/PERF_ALIEN1_MERKLE_BATCH_SIGNING_DESIGN.md` | Profile-linked Merkle batching design for evidence/session signing. |
| `docs/PERF_ALIEN2_ARENA_AUDIT.md` | Allocation-lifetime audit for IR lowering arena candidates. |
| `docs/RGC_S3FIFO_BASELINE_COMPARATOR_V1.md` | S3-FIFO comparator contract and cache workload boundary. |

## Architecture Map

FrankenEngine's load-bearing runtime path is:

```text
source
  -> ts/source normalization
  -> CanonicalEs2020Parser
  -> AST / syntax tree
  -> Ir0Module
  -> lower_ir0_to_ir3
       -> IR1
       -> IR2
       -> IR2 flow proof artifact
       -> IR3 + pass witnesses + isomorphism ledger
  -> LaneRouter
       -> baseline_deterministic_profile
       -> baseline_throughput_profile
  -> ExecutionOrchestrator
       -> guardplane adapter
       -> Bayesian posterior update
       -> expected-loss action selection
       -> evidence ledger
       -> containment executor
       -> execution cell close / replay artifacts
```

The public eval path in `crates/franken-engine/src/lib.rs` follows the same
native core: parse, static break/continue early-error check, lower IR0 to IR3,
patch eval completion value, then execute through `LaneRouter`. The orchestrated
extension path in `execution_orchestrator.rs` adds source ingestion, runtime-flow
guards, guardplane hooks, posterior/risk decisioning, evidence recording,
containment receipts, and execution-cell lifecycle closure.

The CLI surface in `crates/franken-engine/src/bin/frankenctl.rs` is the operator
front door. It exposes compile/check/run/explain/claims/verify/benchmark/replay,
differential oracle, gates, reports, test, synth, orchestration, and runtime
workflows. Any gauntlet proof that claims operator value should either be
reachable through `frankenctl` or through a documented script that emits a
replayable artifact bundle.

## Current Positive Evidence

| Area | Evidence observed in tree | Current interpretation |
| --- | --- | --- |
| Native core execution | `eval_via_native_pipeline`, `lower_ir0_to_ir3`, `LaneRouter`, `ExecutionOrchestrator` are live source paths. | Real native execution path exists; no core-engine binding path was found in the inspected route. |
| Claim language discipline | Matrix rows encode `observed`, `target`, and `hypothesis`; README repeats those definitions. | Release wording is gate-aware rather than purely narrative. |
| Performance methodology | `PERFORMANCE_BASELINE.md` defines magnitude, confidence, honest-gate, determinism, and variance criteria. | Perf wins require statistical and replay proof, not point estimates. |
| H1 evidence-ledger hot path | H1.4/H1.5/H1.6 snapshot cites pass1 baseline and 2026-06-18 remote validation artifacts. | Evidence-ledger signing/cache work has a concrete proof lane. |
| E8 negative evidence | `scripts/e2e/e8_refusal_ledger_smoke.sh check` passed in this pass. | Schema, inventory, fixture, invariant, vocabulary, and script syntax checks are green. |
| Data-contract/E8 runtime hooks | `DataContractRunBinding::uncertified_preflight_receipt*` and `frankenctl run` receipt linkage are present in current working tree. | Live receipt path exists in current tree state; Cargo integration proof is tracked separately below. |
| Alien optimization grounding | Merkle batching, arena lowering, and S3-FIFO each already have bounded design/comparator docs. | Candidate optimizations have local contracts and should not be reinvented ad hoc. |

## Negative Evidence Ledger

| ID | Negative evidence | Consequence | Required promotion proof |
| --- | --- | --- | --- |
| GNT-NEG-001 | `FE-CLAIM-010` remains `target`; no live Node/Bun denominator artifact clears the `>= 3.0x` threshold with `publish_allowed=true` and `repro.lock`. | No observed `>= 3x` Node/Bun throughput claim is allowed. | Fresh `PublicationGateDecision` with both Node and Bun scores `>= 3.0`, complete repro bundle, then promotion gate and claim-matrix gate. |
| GNT-NEG-002 | `FE-CLAIM-016` through `FE-CLAIM-021` remain `hypothesis`; theorem-backed compiler/policy/optimization claims still lack a re-runnable proof bundle or real solver-backed verdicts. | Formal compiler and optimization proof language must stay hypothesis-bound. | Lean/proof producer artifacts, translation-validator proof/counterexample witnesses, real SMT/model-checker outcomes, and aggregate promotion gate. |
| GNT-NEG-003 | E8 refusal-ledger smoke explicitly does not prove live `frankenctl run` emits the receipt. | Refusal vocabulary is validated, but live certifier/capstone proof is not complete. | Focused Cargo/rch integration verdict for data contract receipt emission plus capstone fixtures and external-trust explainer consumption. |
| GNT-NEG-004 | No `.bench-history` directory was found in the current checkout. | Criterion history is artifact-specific; do not infer continuous local bench lineage from absent history. | Preserved benchmark bundles with `run_manifest.json`, raw Criterion estimates, command logs, and `repro.lock`. |
| GNT-NEG-005 | The worktree already contains broad modified and untracked runtime/docs/script changes from other lanes. | This pass must avoid over-attributing uncommitted evidence and must not rewrite shared source without reservations. | File reservations, focused validation commands, and exact ownership notes for any touched files. |
| GNT-NEG-006 | `br ready --format json` returned no ready issues during this pass. | No tracker item was claimed or closed by this gauntlet run. | Re-check Beads readiness and dependencies before tying future implementation work to a bead. |
| GNT-NEG-007 | README states no GitHub release exists yet because GA-exit evidence is incomplete. | The project is not release-promotable based on this pass alone. | GA-exit bundle with every relevant row observed or explicitly downgraded, plus release gates. |

## Correctness, Conformance, And Parity Gates

| Gate family | Existing surface | Gauntlet status |
| --- | --- | --- |
| Unit/integration correctness | Cargo tests across `crates/franken-engine`; focused integration tests such as `data_contract_integration.rs`. | Focused E8 data-contract integration is the current live proof target. Full workspace tests were not started because the tree is broad and dirty. |
| Conformance | Test262 runner/release gate, conformance catalog/vector generation, parser/lowering gap inventories. | Conformance coverage exists as infrastructure; this pass did not promote any new coverage number. |
| Parity | Differential oracle, Node/Bun denominator gates, `frx_lockstep_oracle`, benchmark denominator scoring. | FE-CLAIM-010 remains target until denominator score proof clears threshold. |
| Replay/determinism | Replay coverage gates, runtime explain bundle, deterministic serde, evidence replay checker. | Required as behavior proof for any performance win; no new replay win was claimed here. |
| Negative evidence | Claim matrix, E8 refusal ledger, external trust artifact contract. | Negative refusal evidence is first-class and must block positive wording. |

## Performance Opportunity Matrix

No optimization below should be implemented without the stated baseline,
behavior proof, and follow-up profile. The correct unit of work is one lever at
a time.

| Candidate | Current evidence | Expected payoff | Required behavior proof | Current recommendation |
| --- | --- | --- | --- | --- |
| Evidence/session Merkle batching | `PERF_ALIEN1_MERKLE_BATCH_SIGNING_DESIGN.md` plus H1 evidence-ledger hot path. | Reduce per-entry signature cost by signing one batch root and verifying inclusion proofs. | Golden root/proof vectors, signature preimage domain separation tests, replay equivalence for evidence entries. | High-value only after implementation bead can preserve per-entry auditability. |
| IR lowering arena / scratch buffers | `PERF_ALIEN2_ARENA_AUDIT.md` identifies end-of-pass scratch vectors in lowering. | Reduce allocation churn in lowering hot paths. | IR3 byte/golden equivalence, lowering pass witnesses unchanged except allowed allocation metadata, Criterion win under variance cap. | Plausible next performance lever; requires focused profile and narrow implementation. |
| S3-FIFO cache comparator | `RGC_S3FIFO_BASELINE_COMPARATOR_V1.md` defines incumbent and corpus. | Improve cache retention/pollution behavior with simple FIFO queues and explicit comparator. | Corpus manifest hash, incumbent-vs-candidate report, replay bundle, no invalidation/trust semantics drift. | Keep as bounded comparator lane; do not replace cache policy without bundle. |
| Seqlock snapshot fast path | Source exports `seqlock_*` modules and alien docs identify seqlocks as a read-mostly primitive. | Potential read-path latency reduction for stable snapshots. | Loom/model checks for reader/writer invariants and replay-safe fallback. | Do not implement from this pass; needs measured read-contention hotspot first. |
| Queue/admission controllers | Runtime has queue/admission/control modules; alien docs recommend expected-loss controllers with safe-mode fallback. | Tail-latency improvement under overload. | Decision ledger fields, conservative fallback, replay traces, p95/p99 before/after. | Candidate for a later controller-specific profile, not a blanket rewrite. |

## Current Validation Log

| Command | Result | Notes |
| --- | --- | --- |
| `scripts/e2e/e8_refusal_ledger_smoke.sh check` | PASS | Shell/JQ-only validation for schema, inventory, fixtures, invariants, vocabulary, and script syntax. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch diagnose --dry-run --json -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_e8_data_contract_20260618T_current cargo test -p frankenengine-engine --test data_contract_integration -- --nocapture` | PASS | Classified as `cargo_test` and selected a remote worker. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_e8_data_contract_20260618T_current cargo test -p frankenengine-engine --test data_contract_integration -- --nocapture` | RUNNING | Focused Cargo proof for E8 data-contract receipt integration. |

## Next Gauntlet Rounds

1. Finish the focused E8 data-contract integration proof and record the exact
   first blocker if it fails.
2. Run the claim matrix gate before any claim-state edit:
   `./scripts/run_claim_to_proof_matrix_gate.sh ci`.
3. For performance, pick exactly one candidate with a profile artifact:
   Merkle batching, lowering scratch allocations, or S3-FIFO comparator.
4. For the chosen candidate, freeze the baseline, write golden/isomorphism
   checks, implement one lever, run the focused bench through `rch`, and reject
   the change unless it clears the performance standard in
   `docs/PERFORMANCE_BASELINE.md`.
5. For conformance/parity, prefer differential-oracle and Test262 frontier
   artifacts over new hand-written claims. Any unsupported surface must appear
   as a gap/refusal, not a silent pass.

