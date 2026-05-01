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
| `FE-CLAIM-002` | security | `README.md:38-45` | `target` | downgrade until live guardplane decision artifact exists | `bd-1ypps` |
| `FE-CLAIM-003` | replay | `README.md:46` | `target` | downgrade until replay coverage proof exists | `bd-2488a` |
| `FE-CLAIM-004` | security | `README.md:47` | `hypothesis` | split receipt, transparency-log, and TEE proof before release | `bd-1qkrc` |
| `FE-CLAIM-005` | operations | `README.md:48` | `target` | downgrade until live propagation/convergence proof exists | `bd-1py8v` |
| `FE-CLAIM-006` | security | `README.md:49` | `target` | downgrade until ambient-authority rejection proof exists | `bd-1bao8` |
| `FE-CLAIM-007` | operations | `README.md:55-92` | `observed` | allow documented CLI smoke workflow reference | `bd-3tsah` |
| `FE-CLAIM-008` | operations | `README.md:922-955` | `observed` | allow unsupported-surfaces support policy wording | `bd-1qkrc` |
| `FE-CLAIM-009` | evidence | `README.md:51` | `target` | policy exists; complete publication enforcement remains target | `bd-1qkrc` |
| `FE-CLAIM-010` | performance | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:56-58` | `target` | require denominator-matched Node/Bun benchmark proof | `bd-y6v8s` |
| `FE-CLAIM-011` | security | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:58` | `target` | require red-team compromise-rate comparison proof | `bd-1vwza` |
| `FE-CLAIM-012` | security | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:59-60` | `target` | require signal-to-action timestamp proof | `bd-38mby` |
| `FE-CLAIM-013` | replay | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:60` | `target` | require replay coverage class enumeration | `bd-2488a` |
| `FE-CLAIM-014` | capability | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:61` | `target` | require three named production feature proof bundles | `bd-1qkrc` |
| `FE-CLAIM-015` | ifc | `PLAN_TO_CREATE_FRANKEN_ENGINE.md:94` | `target` | require live declassification source-to-sink proof | `bd-dpfvh` |

## Failure Output

Every gate event emits these fields:

`claim_id`, `claim_scope`, `source_path`, `source_span`, `allowed_state`,
`actual_wording_state`, `artifact_path`, `verification_command`,
`freshness_days`, `decision`, `reason`, `owning_bead`.

Rows that cannot be allowed emit `downgrade_text` in the JSON report so release
authors have exact replacement wording instead of review prose.
