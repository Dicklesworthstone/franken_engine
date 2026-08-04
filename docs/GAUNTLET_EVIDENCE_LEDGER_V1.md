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
| H1 evidence-ledger hot path | H1.4 bench validation and H1.5 replay artifacts cite pass1 baseline and 2026-06-18 remote validation artifacts. | Evidence-ledger signing/cache work has a concrete proof lane, but H1.6/H1.7 smoke evidence remains partially red below. |
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
| GNT-NEG-008 | The S3-FIFO baseline comparator remote body printed `improved_hit_rate_cases=0`, `improved_hot_retention_cases=0`, and `reduced_scan_pollution_cases=0` on the default 5-case corpus, with hit-rate regressions on `cold_compile`, `package_graph`, and `react_app`. The suite then failed closed with `(rch-exit-125)` and did not retrieve the required JSON bundle locally. | S3-FIFO cannot be treated as a performance win or replacement-ready cache policy from this pass. | Clean suite pass with local `cache_trace_corpus_manifest.json`, `cache_policy_baseline_report.json`, adoption wedge, run manifest, event log, command log, repro lock, and no regressing corpus cases unless explicitly accepted by a documented adoption rule. |
| GNT-NEG-009 | `perf_h1_default_key_cache_integration::ten_thousand_sequential_evidence_entries_share_signing_key` was not a current green H1.7 proof. The original test used `i as u8` as a uniqueness proxy for 10,000 entries, which can produce only 256 unique values. After fixing that proxy, repeated rch runs still failed the historical `< 3s` smoke cap with `6.400319784s` and `6.109180158s` on remote workers. The closed bead text says the bound was intended as `< 3 s on the dev box` and that execution was pending due to build locks. | H1.7 cannot currently be cited as a passing integration smoke proof for cached default-key throughput. The H1 performance story must stay anchored to the H1.4/H1.5 artifact chain until this smoke test is recalibrated or replaced by an artifact-backed gate. | Decide whether H1.7 is a dev-box-only smoke or a portable rch gate; then either capture a clean specified-hardware run, replace the wall-clock assertion with the H1.4 artifact gate, or document and approve a new threshold with fresh evidence. |
| GNT-NEG-010 | The checked-in 2026-06-18 H1.6 smoke trail is not a clean full-smoke proof. `h1_smoke/20260618T1650Z` passed quick mode with the bench skipped, while full-mode runs such as `20260618T1720Z`, `20260618T1811Z`, and `20260618T1919Z` passed the evidence-ledger lib/golden checks but failed the `evidence_ledger_bundle` bench leg with no synced estimates (`sample_count=0`, `mean_ns=null`, `bench_status=fail`). A fresh full run, `20260619T0007Z_BEIGEPELICAN`, also failed before the bench: the old script recorded `unit_status=fail`, `bench_status=skipped`, and `mean_ns=null`; `unit.txt` contains compile output through `Compiling frankenengine-engine` but no Cargo test verdict. The local wrapper was terminated with rc=15 after the remote build disappeared from `rch status`. The H1 smoke harness now classifies that same log as `transport_timeout` with reason `ssh_timeout_no_final_verdict`, not as source evidence. | H1.6 cannot currently be cited as a clean end-to-end operator smoke proving the 110 us cap, even though H1.4 remains a passing statistical bench artifact. The latest full attempt is a transport/build-completion blocker, not a failing evidence-ledger test body. | Produce a fresh full `scripts/perf/run_perf_h1_smoke.sh` remote run with synced Criterion estimates, `mean_ns <= 110000`, `bench_stats.json`, `events.jsonl`, `fingerprint.json`, and `summary.md`, or downgrade H1.6 wording to tests-only liveness. |

## Correctness, Conformance, And Parity Gates

| Gate family | Existing surface | Gauntlet status |
| --- | --- | --- |
| Unit/integration correctness | Cargo tests across `crates/franken-engine`; focused integration tests such as `data_contract_integration.rs`. | Focused E8 data-contract integration test body passed; H1.7 default-key cache integration remains red on the 3s smoke cap, and H1.6 full smoke lacks a clean bench leg. Full workspace tests were not started because the tree is broad and dirty. |
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
| `CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT=/tmp/franken_engine_claim_to_proof_matrix_gate_beigepelican_20260618 ./scripts/run_claim_to_proof_matrix_gate.sh ci` | PASS | Shell/JQ-only gate exited 0; report verdict `pass` with 24 events under `/tmp/franken_engine_claim_to_proof_matrix_gate_beigepelican_20260618/20260618T220456Z/`. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch diagnose --dry-run --json -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_e8_data_contract_20260618T_current cargo test -p frankenengine-engine --test data_contract_integration -- --nocapture` | PASS | Classified as `cargo_test` and selected a remote worker. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_e8_data_contract_20260618T_current cargo test -p frankenengine-engine --test data_contract_integration -- --nocapture` | TEST BODY PASS / WRAPPER INTERRUPTED | Cargo printed `test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s`. The local `rch` wrapper remained alive on an SSH child after the green test output and was interrupted after an additional wait; do not treat this as a clean wrapper exit artifact. |
| `S3FIFO_BASELINE_COMPARATOR_ARTIFACT_ROOT=artifacts/s3fifo_baseline_comparator CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_s3fifo_baseline_20260618T2210 RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 RCH_BUILD_TIMEOUT_SECONDS=2400 RCH_EXEC_TIMEOUT_SECONDS=2400 ./scripts/run_s3fifo_baseline_comparator_suite.sh run` | FAIL CLOSED / REMOTE SUMMARY CAPTURED | Suite manifest `artifacts/s3fifo_baseline_comparator/20260618T220917Z/suite_run_manifest.json` reports `outcome=fail` and failed command `(rch-exit-125)`. Step log captured remote summary: corpus hash `0f539cd7b2773005de7bd1c32d6eddf43bc15fa7fed6b204b29478dbb8711a68`, 5 cases, zero improved cases for all win metrics, and hit-rate deltas `cold_compile=-166667`, `package_graph=-285714`, `react_app=-375000`. Required bundle files such as `cache_policy_baseline_report.json` were not present locally. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_h1_cache_20260618T_merkle cargo test -p frankenengine-engine --test perf_h1_default_key_cache_integration -- --nocapture` | FAIL / WRAPPER INTERRUPTED | Original H1.7 test failed at `ten_thousand_sequential_evidence_entries_share_signing_key`: `left: 256`, `right: 10000`, proving the `i as u8` uniqueness proxy was invalid. Cargo also warned that `entry` was unused. The wrapper stayed alive after cargo emitted the failure and was interrupted. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_h1_cache_fix_20260618T cargo test -p frankenengine-engine --test perf_h1_default_key_cache_integration -- --nocapture` | FAIL / WRAPPER INTERRUPTED | After replacing the `u8` proxy with real `entry_id` uniqueness, cargo reached the wall-clock cap and failed: `10k evidence entries took 6.400319784s, expected < 3s`. The wrapper stayed alive after cargo emitted the failure and was interrupted. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_h1_cache_fix2_20260618T cargo test -p frankenengine-engine --test perf_h1_default_key_cache_integration -- --nocapture` | FAIL | After moving uniqueness-set construction outside the timed loop, cargo still failed the historical cap: `10k evidence entries took 6.109180158s, expected < 3s`. Treat H1.7 as red under rch until threshold semantics are resolved. |
| `sed -n '1,220p' tests/artifacts/perf/h1_bench/20260618T1410Z/summary.md` plus events/fingerprint inspection | PASS ARTIFACT INSPECTION | H1.4 bench validation reported `evidence_ledger_bundle` mean `71346.4 ns` vs pass1 `225145.0 ns`, `-68.31%`, CI95 `[70296.4, 72432.0]`, CV `7.7%`, overall PASS. Fingerprint marks the run as `rch_remote` with `cargo_bench` dry-run offload selected. |
| `sed -n '1,220p' tests/artifacts/perf/h1_replay/20260618T144245Z/gate.log` plus metamorphic log inspection | PASS ARTIFACT INSPECTION | H1.5 replay gate generated pass and fail-closed replay coverage artifacts; metamorphic suite reported `relations=12`, `total_pairs=12000`, `violations=0`. |
| H1.6 smoke artifact inspection over `tests/artifacts/perf/h1_smoke/20260618T{1532Z,1606Z,1650Z,1720Z,1811Z,1911Z,1919Z}` | MIXED / FULL SMOKE RED | Quick `20260618T1650Z` passed lib/golden checks with the bench skipped. Full runs `1720Z`, `1811Z`, and `1919Z` passed lib/golden but failed the bench leg with no estimates, so H1.6 is not a clean 110 us cap proof. |
| `H1_SMOKE_RUN_TS=20260619T0007Z_BEIGEPELICAN RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=5400 RCH_EXEC_TIMEOUT_SECONDS=5400 CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_h1_smoke_20260619T0007Z scripts/perf/run_perf_h1_smoke.sh` | FAIL / TRANSPORT INTERRUPTED | Fresh full H1.6 run selected `vmi1264463` for the evidence-ledger lib tests and generated `tests/artifacts/perf/h1_smoke/20260619T0007Z_BEIGEPELICAN/`. `unit.txt` stops at `Compiling frankenengine-engine`; no `Finished`, `Running`, or `test result` line was emitted. `rch status` had no active/recent evidence-ledger build while local `timeout -> rch exec` remained alive, so the local child was terminated; summary records evidence-ledger lib `fail`, golden `skipped`, bench `skipped`, overall `FAIL`. |
| `bash -n scripts/perf/run_perf_h1_smoke.sh` | PASS | H1.6 smoke harness syntax check passed after adding remote Cargo verdict classification. |
| `bash -c 'set -euo pipefail; source <(sed -n "112,221p" scripts/perf/run_perf_h1_smoke.sh); status=$(classify_remote_cargo_log tests/artifacts/perf/h1_smoke/20260619T0007Z_BEIGEPELICAN/unit.txt 15); reason=$(remote_cargo_reason_code "$status"); printf "%s %s\n" "$status" "$reason"; [[ "$status" == transport_timeout && "$reason" == ssh_timeout_no_final_verdict ]]; if status_is_ok "$status"; then exit 2; fi'` | PASS | Existing no-verdict H1.6 `unit.txt` now classifies as `transport_timeout ssh_timeout_no_final_verdict`, and `status_is_ok` rejects it for overall pass computation. |
| `H1_SMOKE_RUN_TS=20260619T0159Z_BEIGEPELICAN_CLASSIFIER scripts/perf/run_perf_h1_smoke.sh --self-check` | PASS | No-Cargo harness self-check emitted `events.jsonl` and `summary.md` under `tests/artifacts/perf/h1_smoke/20260619T0159Z_BEIGEPELICAN_CLASSIFIER/`; the run-complete event verdict is `pass` for self-check mode only. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=2400 timeout 2400 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_check_all_20260619T0100 cargo check --all-targets` | FAIL | Full workspace check exposed a real source/config blocker: `error[E0433]: cannot find module or crate insta in this scope` at `crates/franken-engine-control-plane-integration-tests/../franken-engine/tests/extension_host_lifecycle_integration.rs:264:5`. The moved integration-test crate needed the same `insta` dev-dependency used by the engine/extension-host crates. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=900 timeout 900 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_check_all_20260619T0100 cargo check -p frankenengine-control-plane-integration-tests --test extension_host_lifecycle_integration` | PASS | Focused remote check passed after adding `insta = { version = "1.39", features = ["filters"] }` to `crates/franken-engine-control-plane-integration-tests/Cargo.toml`; remote finished `exit=0` in 435424 ms on `vmi1152480`. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=1800 timeout 1800 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_check_all_20260619T0100 cargo check --all-targets` | FAIL | The next full check exposed a second real source blocker: `error: cannot find derive macro Deserialize in this scope` at `crates/franken-engine/tests/deterministic_serde_golden.rs:32:21`. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=900 timeout 900 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_check_all_20260619T0100 cargo check -p frankenengine-engine --test deterministic_serde_golden` | PASS | Focused remote check passed after importing `serde::Deserialize`; remote finished `exit=0` in 433237 ms on `vmi1152480`. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=1800 timeout 1800 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_check_all_20260619T0100 cargo check --all-targets` | PASS WITH WARNINGS | Final full workspace check passed after both compile fixes; remote finished `exit=0` in 1040762 ms on `vmi1152480`. The run still emitted broad pre-existing rustc warning debt across tests/examples/library-test code, so `cargo clippy --all-targets -- -D warnings` remains an expected separate cleanup blocker rather than a green gate. |
| `cargo fmt --check` | PASS | Formatting gate passed after the harness, ledger, test, and manifest edits. |
| `git diff --check -- scripts/perf/run_perf_h1_smoke.sh docs/GAUNTLET_EVIDENCE_LEDGER_V1.md crates/franken-engine/tests/perf_h1_default_key_cache_integration.rs crates/franken-engine-control-plane-integration-tests/Cargo.toml crates/franken-engine/tests/deterministic_serde_golden.rs Cargo.lock` | PASS | Touched-file diff whitespace check passed. |
| `RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=1800 timeout 1800 rch exec --json --no-self-healing -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_beigepelican_check_all_20260619T0100 cargo clippy --all-targets -- -D warnings` | FAIL | Remote clippy exited `101` in 509563 ms on `vmi1152480`. First blockers are outside this checkpoint's edit scope: `baseline_interpreter.rs:7996` `clippy::type_complexity`, `baseline_interpreter.rs:17577` `clippy::to_string_in_format_args`, `baseline_interpreter.rs:23281` `clippy::manual_unwrap_or`, `baseline_interpreter.rs:25395` `clippy::manual_unwrap_or_default`, `lowering_pipeline.rs:1276` `clippy::collapsible_if`, `pac_bayes_bound.rs:367` `clippy::unnecessary_cast`, and `replay_coverage_metric_gate.rs:65` `clippy::derivable_impls`. |

## Next Gauntlet Rounds

1. Convert the H1 proof chain into one clear source of truth: keep H1.4 as the
   statistical authority, rerun or repair H1.6 full smoke artifact sync, and
   decide whether H1.7 is a dev-box-only regression test or an artifact-backed
   remote gate.
2. Run the claim matrix gate before any claim-state edit:
   `./scripts/run_claim_to_proof_matrix_gate.sh ci`.
3. For performance, pick exactly one candidate with a profile artifact:
   Merkle batching or lowering scratch allocations; S3-FIFO must first fix the
   comparator artifact retrieval/finalization path and explain the current
   negative corpus deltas before any cache replacement work.
4. For the chosen candidate, freeze the baseline, write golden/isomorphism
   checks, implement one lever, run the focused bench through `rch`, and reject
   the change unless it clears the performance standard in
   `docs/PERFORMANCE_BASELINE.md`.
5. For conformance/parity, prefer differential-oracle and Test262 frontier
   artifacts over new hand-written claims. Any unsupported surface must appear
   as a gap/refusal, not a silent pass.
