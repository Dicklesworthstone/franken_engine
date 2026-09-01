# Claim-To-Proof Matrix V1

This report is the human-readable companion to
[`claim_to_proof_matrix_v1.json`](./claim_to_proof_matrix_v1.json). The JSON
file is authoritative for the gate.

Policy source: [`docs/RUNTIME_CHARTER.md`](./RUNTIME_CHARTER.md), section 7.

Gate command:

```bash
./scripts/run_claim_to_proof_matrix_gate.sh ci
```

## State Rules

| State | Meaning |
|---|---|
| `observed` | Current artifacts and a verification command are linked. |
| `target` | A design goal or SLO is documented, but observed proof is not linked yet. |
| `hypothesis` | Projected or optional behavior that must not be read as shipped proof. |

The gate fails when `actual_wording_state` is stronger than `allowed_state`, when
source spans drift, when observed rows lack artifact handles, or when missing
proof lacks exact downgrade text.

## Performance Evidence

The real hot-path lane is observed internal FrankenEngine evidence only when
`scripts/run_real_hot_path_proof.sh smoke` emits `real_runtime_hot_paths`
artifacts and `scripts/real_hot_path_proof_contract_gate.sh` validates the
deterministic command, rch worker, target-dir, digest, metric, and proof-state
contract.

That lane does not promote the Node/Bun denominator claim. The preserved June
2026 bundle records a dirty-worktree, unweighted geometric mean of `0.000920x`
Node over 16 admitted cases and `0.000791x` Bun over 13. It links a 31-case
manifest but contains 28 results, uses asymmetric engine/reference lifecycles,
and its `repro.lock` reproduces correctness rather than timing. It is a
non-normative historical baseline, not the plan's weighted denominator
contract. `FE-CLAIM-010` therefore remains `target`. Artifacts containing
`hot_paths_simulation` or `MockCertificate` are fixture-only and the gate
rejects them as backing evidence for observed performance claims.

Operator workflow, failure triage, and comparison steps live in
`docs/REAL_HOT_PATH_EVIDENCE_RUNBOOK.md`.

## Matrix

| Claim | Scope | Source | State | Decision | Owner |
|---|---|---|---|---|---|
| `FE-CLAIM-001` | runtime | `README.md:17` | `observed` | allow observed native-runtime wording with release-gate caveat | `bd-1qkrc` |
| `FE-CLAIM-002` | security | `README.md:137` | `observed` | allow observed probabilistic guardplane with live decision artifacts | `bd-1ypps` |
| `FE-CLAIM-003` | replay | `README.md:138` | `observed` | allow observed replay coverage, counterfactual replay support, and fixed-input CLI artifact proof | `bd-2488a` |
| `FE-CLAIM-004` | security | `README.md:139` | `observed` | allow observed signed-decision-receipt surface: receipt proof handle (`bd-cixqu.1.1`) + transparency log with MMR inclusion/consistency proofs (`bd-cixqu.1.2`), cross-referenced by the RGC gate + replay (`bd-cixqu.1.4`). TEE attestation split out to `FE-CLAIM-004-TEE` by CEI-C.1 | `bd-1qkrc` |
| `FE-CLAIM-004-TEE` | security | `README.md:139` | `hypothesis` | downgrade until a real TEE SDK + live-quote proof artifacts ship — `tee_live_quote.rs` simulates every quote by default (`tee-real-sdk` unwired) | `bd-sde5e.3.1` |
| `FE-CLAIM-005` | operations | `README.md:140` | `target` | harness/SLO/fault profiles exist; published CI gate checks shape and source references but does not execute or preserve measured convergence percentiles | `bd-cixqu.2.5` |
| `FE-CLAIM-006` | security | `README.md:141` | `observed` | compile-time capability-typed ambient-authority rejection on the shipped hostcall/import edges (effect_set IR2, lowering refusal, 17-scenario red-team corpus, RGC gate + replay). The end-to-end TS-to-IR contract over all ambient constructs is TARGETED (CEI-C.2) | `bd-cixqu.3.5` |
| `FE-CLAIM-TEST262` | conformance | `README.md:545` | `target` | downgrade until full tc39/test262 corpus conformance — the shipped gate runs a provisional checked-in subset (`full_suite_claim_allowed=false`) | `bd-sde5e.4.1` |
| `FE-CLAIM-007` | operations | `README.md:93-99` | `observed` | allow documented CLI smoke workflow reference | `bd-3tsah` |
| `FE-CLAIM-008` | operations | `README.md:2422` | `observed` | allow unsupported-surfaces support policy wording | `bd-1qkrc` |
| `FE-CLAIM-009` | evidence | `README.md:215` | `observed` | when invoked, gate refuses OBSERVED state without repro.lock; continuous CI invocation and producer re-execution are not established | `bd-cixqu.4.4` |
| `FE-CLAIM-010` | performance | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:56-58` | `target` | historical bundle is unweighted, dirty-worktree, lifecycle-asymmetric, 28 results against a 31-case manifest, and correctness-lock-only; weighted denominator target remains open | `bd-y6v8s` |
| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `target` | exact v2 producer, scoped replay, and sole Rust verdict path ship over ten contract-declared scenarios with 100 stability repetitions per runtime/scenario pair and a one-scenario zero-cell guard; promotion still waits on a current non-fixture v2 campaign plus passing linked verdict | `bd-1vwza` |
| `FE-CLAIM-012` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:59-60` | `target` | downgraded observed->target (CEI B.2): no production-measured containment-latency artifact; the gate fails closed without `CONTAINMENT_LATENCY_METRIC_INPUT` | `bd-38mby` |
| `FE-CLAIM-013` | replay | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:60` | `observed` | allow observed replay coverage gate plus fixed-input CLI determinism proof (compile byte-identical; run modulo per-invocation signing authority) | `bd-2488a` |
| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | two independently observed features ship; the third catalog entry depends on FE-CLAIM-011, whose exact v2 producer and verdict gate ship but still lack a current non-fixture campaign plus passing linked Rust verdict, so the three-feature floor is not met | `bd-cixqu.6.6` |
| `FE-CLAIM-015` | ifc | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:96` | `observed` | allow observed IFC with signed declassification receipts | `bd-dpfvh` |
| `FE-CLAIM-016` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:50` | `hypothesis` | STAY_HYPOTHESIS (G.10): the default Lean build omits capability-algebra targets that fail direct checking, while the producer inventories theorem names from every Lean source; no sound current `.proof.json` closes the full target set | `bd-csnqb` |
| `FE-CLAIM-017` | compiler | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:593` | `hypothesis` | STAY_HYPOTHESIS (G.10): differential validators and a proof-bundle helper exist, but no product/operator producer emits a non-fixture witness over a real non-empty compiler transformation | `bd-csnqb` |
| `FE-CLAIM-018` | policy | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:611` | `hypothesis` | STAY_HYPOTHESIS (G.10): real Z3-backed theorem verification and a bundle emitter exist, but the live promotion gate has no qualifying current FE-CLAIM-018 proof bundle | `bd-csnqb` |
| `FE-CLAIM-019` | optimization | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:636` | `hypothesis` | STAY_HYPOTHESIS (G.10): obligations route through Z3 or bounded fail-closed sample runners, but no qualifying non-fixture full-optimization proof bundle exists | `bd-csnqb` |
| `FE-CLAIM-020` | policy | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:744` | `hypothesis` | STAY_HYPOTHESIS (G.10): no current end-to-end bundle composes qualifying FE-CLAIM-018/019/021 evidence into a theorem-backed compiler proof | `bd-csnqb` |
| `FE-CLAIM-021` | policy | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:828-898` | `hypothesis` | STAY_HYPOTHESIS (G.10): real Z3-backed monotonicity/non-interference/attenuation machinery exists, but the live promotion gate has no qualifying current FE-CLAIM-021 proof bundle | `bd-csnqb` |
| `FE-CLAIM-022` | runtime | `README.md:1408` | `observed` | cross-runtime lockstep oracle (Node/Bun differential harness, divergence taxonomy, RGC gate + replay); the real Node lane runs against `/usr/bin/nodejs` (CEI B.2) | `bd-cixqu.9` |
| `FE-CLAIM-023` | reproducibility | `README.md:1768` | `target` | downgraded observed->target (CEI B.2): cross-platform identical-hash evidence (Linux/macOS/Windows × x64/arm64) requires the multi-platform CI matrix; a single host backs only the Linux×x64 lane | `bd-cixqu.11.7` |
| `FE-CLAIM-024` | integration | `README.md:2116` | `observed` | sibling-repo integration verification across all 6 declared siblings (bd-cixqu.13.1 full-integration lane records pass/skipped/failed per sibling) | `bd-cixqu.13.3` |
| `FE-CLAIM-025` | evidence | `README.md:2491` | `observed` | CEI H.2 reflexive soundness: the integrity capstone composes the A.1/A.3 lattice + H.1 Merkle ledger + wording gate + D.3 Test262 posture; 025's own row is ledger-committed, the A.5 adversarial corpus rejects over-promotion fixtures, and the G.3 no-mock drill reddens the capstone on any injected over-promotion; H.4 machine-checks the state<=ceiling(tier) meta-soundness lemma in Lean 4 (proofs/lean4/ClaimEvidenceSoundness.lean, scripts/run_cei_soundness_lean_proof.sh, sorryAx-free) | `bd-sde5e.8.2` |
| `FE-CLAIM-026` | conformance | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:1419-1432` | `target` | weighted ES2020 coverage summary linked (`docs/coverage/es2020_coverage_summary_bundle_v1`, bd-fqlfw.7.4); the engine EXECUTES 6201/47514 = ~13.05% of the observable surface (executed = evaluated without an engine error / correctly rejected; NOT a conformance pass-rate — the stricter harness-based conformance is far lower, ~0.25%, `docs/test262_real_corpus_pass_rate_v1.json`); weakest view `builtin` (~1.67%); six weighted views + a floor prevent a single gamed percentage, so stays target | `bd-fqlfw.7.4` |

## Failure Output

Every gate event emits these fields:

`claim_id`, `claim_scope`, `source_path`, `source_span`, `allowed_state`,
`actual_wording_state`, `artifact_path`, `verification_command`,
`freshness_days`, `decision`, `reason`, `owning_bead`.

Rows that cannot be allowed emit `downgrade_text` in the JSON report so release
authors have exact replacement wording instead of review prose.
