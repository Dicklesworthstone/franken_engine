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

That lane does not promote the Node/Bun denominator claim. `FE-CLAIM-010`
remains `target` until fresh Node and Bun denominator artifacts satisfy the
benchmark denominator contract. Artifacts containing `hot_paths_simulation` or
`MockCertificate` are fixture-only and the gate rejects them as backing evidence
for observed performance claims.

Operator workflow, failure triage, and comparison steps live in
`docs/REAL_HOT_PATH_EVIDENCE_RUNBOOK.md`.

## Matrix

| Claim | Scope | Source | State | Decision | Owner |
|---|---|---|---|---|---|
| `FE-CLAIM-001` | runtime | `README.md:17` | `observed` | allow observed native-runtime wording with release-gate caveat | `bd-1qkrc` |
| `FE-CLAIM-002` | security | `README.md:137` | `observed` | allow observed probabilistic guardplane with live decision artifacts | `bd-1ypps` |
| `FE-CLAIM-003` | replay | `README.md:138` | `observed` | allow observed replay coverage, counterfactual replay support, and fixed-input CLI artifact proof | `bd-2488a` |
| `FE-CLAIM-004` | security | `README.md:139` | `hypothesis` | split receipt, transparency-log, and TEE proof before release | `bd-1qkrc` |
| `FE-CLAIM-005` | operations | `README.md:140` | `target` | downgrade until live quarantine propagation proof exists | `bd-ls22h` |
| `FE-CLAIM-006` | security | `README.md:141` | `observed` | compile-time capability-typed rejection via C.1-C.4 (effect_set IR2, lowering refusal, 16-scenario red-team corpus, RGC gate + replay) | `bd-cixqu.3.5` |
| `FE-CLAIM-007` | operations | `README.md:93-99` | `observed` | allow documented CLI smoke workflow reference | `bd-3tsah` |
| `FE-CLAIM-008` | operations | `README.md:2307` | `observed` | allow unsupported-surfaces support policy wording | `bd-1qkrc` |
| `FE-CLAIM-009` | evidence | `README.md:213` | `observed` | gate refuses OBSERVED state without repro.lock (bd-cixqu.4.3); all OBSERVED rows have reproducibility bundles | `bd-cixqu.4.4` |
| `FE-CLAIM-010` | performance | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:56-58` | `target` | downgrade until live Node/Bun denominator artifacts replace targeted placeholder throughput evidence | `bd-y6v8s` |
| `FE-CLAIM-011` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `observed` | allow observed red-team compromise-rate comparison with baseline validation | `bd-1vwza` |
| `FE-CLAIM-012` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:59-60` | `observed` | allow observed signal-to-action timestamp computation with latency artifacts | `bd-38mby` |
| `FE-CLAIM-013` | replay | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:60` | `observed` | allow observed replay coverage gate plus byte-identical fixed-input CLI artifact proof | `bd-2488a` |
| `FE-CLAIM-014` | capability | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `observed` | three named production feature proof bundles ship (IFC declassification, deterministic replay, red-team compromise rate) — F.5 gate `scripts/run_rgc_production_feature_catalog.sh` validates all three with per-feature sha256 manifest hashes | `bd-cixqu.6.6` |
| `FE-CLAIM-015` | ifc | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:96` | `observed` | allow observed IFC with signed declassification receipts | `bd-dpfvh` |
| `FE-CLAIM-016` | security | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:50` | `hypothesis` | downgrade until formal mathematical specification exists | `bd-csnqb` |
| `FE-CLAIM-017` | compiler | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:593` | `hypothesis` | downgrade until proof-carrying compilation artifacts exist | `bd-csnqb` |
| `FE-CLAIM-018` | policy | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:611` | `hypothesis` | downgrade until formal policy semantics proofs exist | `bd-csnqb` |
| `FE-CLAIM-019` | optimization | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:636` | `hypothesis` | downgrade until isomorphism equivalence proofs exist | `bd-csnqb` |
| `FE-CLAIM-020` | policy | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:744` | `hypothesis` | downgrade until theorem-backed compiler exists | `bd-csnqb` |
| `FE-CLAIM-021` | policy | `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md:828-898` | `hypothesis` | downgrade until Policy Theorem Engine with formal verification exists | `bd-csnqb` |

## Failure Output

Every gate event emits these fields:

`claim_id`, `claim_scope`, `source_path`, `source_span`, `allowed_state`,
`actual_wording_state`, `artifact_path`, `verification_command`,
`freshness_days`, `decision`, `reason`, `owning_bead`.

Rows that cannot be allowed emit `downgrade_text` in the JSON report so release
authors have exact replacement wording instead of review prose.
