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

## Matrix

| Claim | Scope | Source | State | Decision | Owner |
|---|---|---|---|---|---|
| `FE-CLAIM-001` | runtime | `README.md:16` | `observed` | allow observed native-runtime wording with release-gate caveat | `bd-1qkrc` |
| `FE-CLAIM-002` | security | `README.md:38-45` | `observed` | allow observed probabilistic guardplane with live decision artifacts | `bd-1ypps` |
| `FE-CLAIM-003` | replay | `README.md:47` | `observed` | allow observed replay coverage, counterfactual replay support, and fixed-input CLI artifact proof | `bd-2488a` |
| `FE-CLAIM-004` | security | `README.md:47` | `hypothesis` | split receipt, transparency-log, and TEE proof before release | `bd-1qkrc` |
| `FE-CLAIM-005` | operations | `README.md:49` | `target` | downgrade until live quarantine propagation proof exists | `bd-ls22h` |
| `FE-CLAIM-006` | security | `README.md:49` | `target` | downgrade until ambient-authority rejection proof exists | `bd-1bao8` |
| `FE-CLAIM-007` | operations | `README.md:55-92` | `observed` | allow documented CLI smoke workflow reference | `bd-3tsah` |
| `FE-CLAIM-008` | operations | `README.md:922-955` | `observed` | allow unsupported-surfaces support policy wording | `bd-1qkrc` |
| `FE-CLAIM-009` | evidence | `README.md:51` | `target` | policy exists; complete publication enforcement remains target | `bd-1qkrc` |
| `FE-CLAIM-010` | performance | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:56-58` | `target` | downgrade until live Node/Bun denominator artifacts replace targeted placeholder throughput evidence | `bd-y6v8s` |
| `FE-CLAIM-011` | security | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `observed` | allow observed red-team compromise-rate comparison with baseline validation | `bd-1vwza` |
| `FE-CLAIM-012` | security | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:59-60` | `observed` | allow observed signal-to-action timestamp computation with latency artifacts | `bd-38mby` |
| `FE-CLAIM-013` | replay | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:60` | `observed` | allow observed replay coverage gate plus byte-identical fixed-input CLI artifact proof | `bd-2488a` |
| `FE-CLAIM-014` | capability | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | require three named production feature proof bundles | `bd-1qkrc` |
| `FE-CLAIM-015` | ifc | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:94` | `observed` | allow observed IFC with signed declassification receipts | `bd-dpfvh` |
| `FE-CLAIM-016` | security | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:50` | `hypothesis` | downgrade until formal mathematical specification exists | `bd-csnqb` |
| `FE-CLAIM-017` | compiler | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:588` | `hypothesis` | downgrade until proof-carrying compilation artifacts exist | `bd-csnqb` |
| `FE-CLAIM-018` | policy | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:606` | `hypothesis` | downgrade until formal policy semantics proofs exist | `bd-csnqb` |
| `FE-CLAIM-019` | optimization | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:631` | `hypothesis` | downgrade until isomorphism equivalence proofs exist | `bd-csnqb` |
| `FE-CLAIM-020` | policy | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:739` | `hypothesis` | downgrade until theorem-backed compiler exists | `bd-csnqb` |
| `FE-CLAIM-021` | policy | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:828-898` | `hypothesis` | downgrade until Policy Theorem Engine with formal verification exists | `bd-csnqb` |

## Failure Output

Every gate event emits these fields:

`claim_id`, `claim_scope`, `source_path`, `source_span`, `allowed_state`,
`actual_wording_state`, `artifact_path`, `verification_command`,
`freshness_days`, `decision`, `reason`, `owning_bead`.

Rows that cannot be allowed emit `downgrade_text` in the JSON report so release
authors have exact replacement wording instead of review prose.
