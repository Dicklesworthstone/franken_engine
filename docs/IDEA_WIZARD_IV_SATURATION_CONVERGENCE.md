# IDEA-WIZARD-IV Saturation Convergence

`bd-vaths.1` defines the V1 contract for the IDEA-WIZARD-IV saturation
convergence and proof-integrity wave. The machine-readable contract is
[`docs/idea_wizard_iv_saturation_convergence_v1.json`](./idea_wizard_iv_saturation_convergence_v1.json).

This contract exists because an empty ready queue is not, by itself, evidence
that the project is saturated. The wave must distinguish a truly saturated
backlog from blind spots such as stale tracker state, weak closeout evidence,
red coordination services, missing validation-impact guidance, or hidden local
Cargo fallback.

The contract is advisory only. It does not claim beads, reopen beads, close
beads, send Agent Mail, repair Agent Mail, run Cargo, run RCH, mutate git,
change queue policy, or touch target directories.

## Reused Surfaces

The wave composes existing controls rather than reimplementing them:

| Existing surface | Reused capability |
| --- | --- |
| `swarm_actionability_truth_gate` | br/bv divergence, stale-source, dirty-overlap, observe-only claim policy |
| `swarm_proof_broker` | proof request fingerprints, proof freshness, reuse refusal, contaminated proof language |
| `swarm_live_readonly_capture_profile` | read-only br, bv, git, RCH, and optional Agent Mail capture policy |
| `agent_mail_outage_continuity_bridge` | degraded Agent Mail visibility and br soft-lock fallback |
| `swarm_resource_envelope` | host, disk, target-dir, RCH capacity, and pressure evidence |
| `swarm_rch_stall_rehabilitation_ledger` | remote stall and local-fallback fail-closed contamination semantics |
| `objective_artifact_completion_audit_gate` | objective-to-artifact and validation-evidence comparison vocabulary |

Any child bead that overlaps these surfaces must name the duplicate reference
and either consume it directly or narrow its scope. A candidate that redefines
proof fingerprints, actionability policy, Agent Mail repair authority, RCH
local-fallback semantics, or resource-envelope policy must fail closed as
`FE-IW4-DUPLICATE-SURFACE`.

## New Wave Scope

| New surface | Owning bead | Scope |
| --- | --- | --- |
| `saturation_convergence_contract` | `bd-vaths.1` | Contract, schema, reason codes, mutation boundary, and smoke validation |
| `closed_bead_proof_integrity_normalizer` | `bd-vgj5t` | Closed-bead to commit, validation, and artifact evidence normalization |
| `coordination_health_repair_packet` | `bd-o9wbd` | Advisory packet for red or unavailable Agent Mail and br fallback state |
| `validation_impact_planner` | `bd-k53rr` | Cheapest trustworthy rch-backed validation recommendation for a change set |
| `resource_proof_heatmap_integrator` | `bd-my2jw` | High-core resource, proof-cache, and RCH pressure heatmap composition |
| `zero_ready_saturation_no_mock_drill` | `bd-aqijn` | No-mock replayable drill for zero-ready, red-mail, healthy-RCH scenarios |
| `saturation_operator_truth_gate` | `bd-ks5p4` | Operator status and docs truth gate for saturation-control claims |
| `saturation_acceptance_suite` | `bd-w06ui` | Final acceptance manifest and replay gate for the whole wave |

## Zero-Ready Classifications

The control plane must classify an empty ready queue into one of these stable
states:

- `true_saturation`: br, bv, git, coordination health, proof evidence, and
  validation-impact packets are all fresh enough to support no-action guidance.
- `tracker_blind_spot`: br JSONL/DB freshness, lock state, or br/bv divergence
  prevents trusting the ready count.
- `coordination_degraded`: Agent Mail or reservation evidence is red,
  unavailable, stale, or malformed. The report may continue only with explicit
  degraded status and br soft-lock fallback.
- `proof_integrity_gap`: closed beads lack enough commit, validation, artifact,
  or closeout evidence to support saturation.
- `validation_map_missing`: the next safe proof command cannot be recommended
  from the changed files, bead labels, and known crate/test ownership.
- `resource_pressure_blocked`: RCH, target-dir, proof-cache, worker, disk, or
  pressure signals require deferral, sharding, or degraded operator guidance.

`true_saturation` is the only green state. All other states are degraded or
fail-closed evidence states.

## Mutation Boundary

All surfaces in this wave are proof-only and advisory-only. They may read
preserved inputs and emit deterministic artifacts. They must not:

- update, claim, reopen, close, defer, or reassign beads
- send, acknowledge, or repair Agent Mail
- release file reservations
- run Cargo or RCH from the contract validation path
- mutate git state or remote worker state
- delete, clean, or overwrite target directories
- change live queue, admission, resource, or validation policy

Implementation child beads may emit recommended commands, but recommendations
are not executed by these surfaces.

## RCH Policy

Heavy Rust validation may appear only as recommended command evidence, and every
heavy Cargo example must be wrapped with an explicit RCH target directory:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_saturation CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets
```

Bare heavy Cargo, missing `CARGO_TARGET_DIR`, shell shapes that can hide local
fallback, and transcripts containing `[RCH] local` cannot be green proof. They
must be reported as fail-closed or contaminated evidence.

Lightweight local validation for this contract is limited to JSON shape checks,
shell syntax checks, text scans, and `git diff --check`.

## Artifact Contract

Every implementation child surface must produce deterministic artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- one machine report named by the surface contract
- one operator Markdown report

Reports must include `schema_version`, `source_revision`, `generated_at_utc`,
`decision`, `classification`, `source_freshness`, `mutation_policy`,
`rch_policy`, `artifact_paths`, and `fail_closed_reasons`.

## README and Operator Claim Language

Until all child beads and the acceptance suite are closed with replay evidence,
operator-facing copy must use targeted language:

> The saturation convergence control plane is an advisory proof contract. It
> can classify preserved zero-ready and degraded-coordination evidence, but it
> does not automatically reopen work, repair Agent Mail, mutate queue policy, or
> prove project-wide completion without the required artifact bundle.

After the acceptance suite is green, docs may say that the gate is observed for
the covered scenarios only. Production or project-wide saturation claims still
require live evidence tied to the exact source revision.

## Validation

```bash
jq empty docs/idea_wizard_iv_saturation_convergence_v1.json
bash -n scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
rg -n 'rch exec -- env CARGO_TARGET_DIR=' docs/IDEA_WIZARD_IV_SATURATION_CONVERGENCE.md docs/idea_wizard_iv_saturation_convergence_v1.json
git diff --check -- docs/IDEA_WIZARD_IV_SATURATION_CONVERGENCE.md docs/idea_wizard_iv_saturation_convergence_v1.json scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh
```
