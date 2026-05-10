# IDEA-WIZARD-III Swarm Proof Economy

`bd-waani` defines the V1 contract for the IDEA-WIZARD-III proof-economy and
degraded-coordination wave. The machine-readable contract is
[`docs/idea_wizard_iii_swarm_proof_economy_v1.json`](./idea_wizard_iii_swarm_proof_economy_v1.json).

This document is an overlap map and operator contract. It is not a scheduler,
proof broker, Agent Mail repair tool, RCH runner, worker controller, dashboard
replacement, or bead closer.

## Reused Surfaces

The wave must reuse existing surfaces before creating new implementation
authority:

| Existing surface | Reused capability |
| --- | --- |
| `swarm_control_surface_catalog` | Catalog row vocabulary, duplicate-surface detection, advisory-only mutation policy |
| `swarm_proof_broker` | Proof request fingerprinting, verdict receipts, stale and contaminated proof semantics |
| `swarm_proof_command_preflight` | RCH-safe command-shape classification before proof scheduling |
| `swarm_live_readonly_capture_profile` | Read-only br, bv, git, RCH, and optional Agent Mail capture policy |
| `swarm_actionability_truth_gate` | Observe-only br/bv actionability, dirty-overlap, and stale-source behavior |
| `swarm_rch_stall_rehabilitation_ledger` | Remote-stall and local-fallback fail-closed contamination language |
| `swarm_resource_envelope` | Host, disk, target-dir, and RCH capacity evidence |
| `swarm_frankentui_dashboard_bundle` | Data-only frankentui panel boundary |

Any child bead that overlaps these behaviors must name the duplicate reference
and either consume it directly or narrow its scope. A candidate that redefines
proof fingerprints, live capture, RCH policy, or Agent Mail recovery semantics
must fail closed as `FE-IW3-DUPLICATE-SURFACE`.

## New Wave Scope

The new work is limited to coordination and composition that is not already
owned by the reused surfaces:

| New surface | Owning bead | Scope |
| --- | --- | --- |
| `all_target_cargo_proof_shard_planner` | `bd-j3lwi` | Split check, clippy, and test proof demand into advisory RCH-safe shards |
| `rch_cache_miss_forensic_ledger` | `bd-n4dfb` | Explain cache misses and proof freshness drift from existing transcripts |
| `agent_mail_outage_continuity_bridge` | `bd-dl3q2` | Make red or unavailable Agent Mail visible and fall back to br soft locks |
| `objective_artifact_completion_audit_gate` | `bd-w8jfe` | Compare objective, changed artifacts, bead status, and validation evidence |
| `swarm_handoff_capsule_generator` | `bd-d5kxj` | Emit deterministic handoff capsules from read-only coordination evidence |
| `high_core_validation_pressure_dashboard_v2` | `bd-f7zfw` | Compose capacity and proof pressure into a data-only panel payload |
| `degraded_coordination_no_mock_drill` | `bd-y59d4` | Compose degraded mail, local fallback fail-closed, stale proof, and dirty path scenarios |
| `idea_wizard_iii_operator_truth_gate` | `bd-99t7y` | Keep docs and help text aligned with the machine contract |
| `idea_wizard_iii_acceptance_suite` | `bd-mwg76` | Prove the wave composes without reimplementing older surfaces |

## Mutation Boundary

All artifacts in this wave are advisory-only, proof-only, and fixture-first.
They must not:

- update, claim, reopen, close, or reassign beads
- release reservations
- send Agent Mail or repair the Agent Mail database
- query live Agent Mail during validation
- run Cargo locally
- start `rch exec`
- mutate git, remote workers, queue policy, or target directories

When Agent Mail is unavailable, the visible state is `degraded`. The continuity
fallback is the current `br` assignee, bead status, and dirty-path scope. The
fallback records risk; it does not pretend reservations or acknowledgements were
successfully exchanged.

## RCH Policy

Heavy Rust validation may appear only as command evidence or recommended proof
text. Every heavy Cargo example must use direct RCH invocation with an explicit
target directory:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_idea_wizard_iii CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets
```

Bare heavy Cargo, shell-wrapped RCH that can fall open into local execution,
missing `CARGO_TARGET_DIR`, and local-fallback transcripts fail closed and are not green proof.
They must be reported as blocked, contaminated, or fail-closed depending on the
surface contract.

## Proof Freshness

Proof freshness is anchored to source revision, dependency scope, RCH posture,
target-dir policy, artifact hashes, and explicit TTL. A stale or contaminated
receipt cannot close a bead. Optional missing Agent Mail evidence may degrade a
report only when the missing source is visible in the emitted artifact.

## Replay Policy

Each child surface starts fixture-first and must emit replayable artifacts:

- machine JSON report
- `events.jsonl`
- `commands.txt`
- operator `report.md`
- source revision or transcript hash evidence

Live capture is allowed only where the machine contract marks it read-only. A
live capture must not perform the mutation it observes.

## Validation

```bash
jq empty docs/idea_wizard_iii_swarm_proof_economy_v1.json
jq -e 'all(.surfaces[]; has("surface_id") and has("source_inputs") and has("emitted_artifacts") and has("mutation_policy") and has("rch_policy") and has("degraded_mail_policy") and has("proof_freshness_policy") and has("replay_policy") and has("owning_bead_id") and has("duplicate_surface_refs"))' docs/idea_wizard_iii_swarm_proof_economy_v1.json
jq -e '.overlap_controls.duplicate_surface_refusal_fixture.expected_outcome == "reject_duplicate_surface" and (.overlap_controls.duplicate_surface_refusal_fixture.candidate_surface.duplicate_surface_refs | length > 0)' docs/idea_wizard_iii_swarm_proof_economy_v1.json
rg -n 'rch exec -- env .*CARGO_TARGET_DIR' docs/IDEA_WIZARD_III_SWARM_PROOF_ECONOMY.md docs/idea_wizard_iii_swarm_proof_economy_v1.json
git diff --check -- docs/IDEA_WIZARD_III_SWARM_PROOF_ECONOMY.md docs/idea_wizard_iii_swarm_proof_economy_v1.json
```
