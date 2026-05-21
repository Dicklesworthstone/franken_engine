# Fleet Convergence Diagnostics + De-Escalation Procedure

Operator runbook for the FrankenEngine fleet-immune protocol: how to
diagnose convergence lag, how to detect partitions, and how to drive
the signed re-admission flow that lifts a quarantined extension back
into the active fleet without silently resetting the trust ratchet.

## What "fleet convergence" means

When an extension misbehaves, the runtime quarantines it. The
quarantine decision is gossiped across the fleet; every node converges
to a consistent view of which extensions are quarantined and at what
security epoch. The SLO is "bounded convergence": every node sees
every quarantine decision within a declared time window of the
originating node's decision.

Re-admission is the inverse: an operator decides that a quarantined
extension may resume, signs the decision with the quarantine's
ratchet semantics intact (re-admission is NEW evidence, not a
quiet rollback), and gossips the signed re-admission back across the
fleet. The same convergence SLO applies in reverse.

This runbook covers both halves: diagnose convergence lag / partition
detection, and drive the re-admission flow.

## Bead anchors

- Track parent: **bd-cixqu.2** (FE-CLAIM-005 — Track B: fleet
  quarantine convergence SLO + de-escalation).
- This document: **bd-cixqu.2.7** (B.7 operator-runbook).
- Engine surface:
  - `crates/franken-engine/src/fleet_convergence.rs` — convergence
    accountant + bounded-time SLO.
  - `crates/franken-engine/src/quarantine_mesh_gate.rs` — quarantine
    mesh gate (per-node enforcement + cross-node gossip).
  - `crates/franken-engine/src/quarantine_propagation.rs` — gossip
    propagation across the mesh.
  - `crates/franken-engine/src/fleet_immune_protocol.rs` —
    high-level fleet-immune contract.
- Sibling runbook (same pattern):
  [`LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`](./LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md).

## Diagnosing convergence lag

The operator-facing snapshot has three layers; read them in order.

### Layer 1 — Fleet quorum state

Inspect `artifacts/fleet_convergence/<run_id>/quorum_snapshot.json`.
This is the convergence accountant's snapshot at the moment of the
diagnostic capture:

| Field | What it tells you |
|---|---|
| `epoch_id` | The security epoch the snapshot is bound to. Cross-epoch comparison is meaningless; confirm this matches the operator's expected epoch. |
| `node_count_observed` | How many nodes the convergence accountant has heard from in this window. |
| `node_count_declared` | How many nodes the fleet manifest says exist. |
| `quorum_reached` | Boolean — `true` when `node_count_observed / node_count_declared >= quorum_threshold_millionths / 1_000_000`. |
| `quorum_threshold_millionths` | The fixed-point ratio. Default 666_666 (~2/3); deployment lanes may set higher. |
| `lagging_nodes` | Array of `node_id` values that have NOT acknowledged the latest published quarantine decision within the SLO window. The first signal of a partition. |

**Interpretation**:

- `quorum_reached == true` + `lagging_nodes` empty → fleet is converged.
- `quorum_reached == true` + `lagging_nodes` non-empty → bounded
  partition. The lagging nodes have not heard, but quorum decisions
  are still safe to publish.
- `quorum_reached == false` → unbounded partition. Quarantine
  decisions published now are NOT safe; they have not reached
  quorum, and a competing decision on the other side of the
  partition can produce divergent fleet state.

### Layer 2 — Partition detection

If `quorum_reached == false` OR `lagging_nodes` is unexpectedly large,
inspect `artifacts/fleet_convergence/<run_id>/partition_report.json`.
The partition detector splits the observed mesh graph into
strongly-connected components based on recent gossip success/failure:

| Field | Meaning |
|---|---|
| `partition_count` | Number of disjoint components the detector observed. 1 = healthy; >1 = partitioned. |
| `components[]` | One entry per component, each with `node_ids[]`, `last_gossip_success_utc`, and `largest_component_size_fraction_millionths`. |
| `partition_class` | `Transient` / `Persistent` / `Permanent` — see the classification table below. |

Partition classification:

| `partition_class` | Signal | Action |
|---|---|---|
| `Transient` | Detected during a single diagnostic window; both sides had recent successful gossip exchanges. | Re-run the convergence accountant after the gossip-window cool-off (usually 30 seconds). If the partition resolves, no action required beyond noting it in the operator log. |
| `Persistent` | Detected across multiple diagnostic windows; no successful cross-component gossip for the SLO duration. | Pause new quarantine publications. Investigate the network path between components — the runtime cannot resolve this by retry. |
| `Permanent` | Persistent partition that has now exceeded the lifetime convergence budget. | Either bring the components back together (network repair) OR explicitly split-brain the fleet: each component runs as its own logical fleet, with its own quarantine ledger, and re-merge is a separate signed operator action. |

### Layer 3 — Per-node convergence lag

For the `lagging_nodes` array from Layer 1, inspect
`artifacts/fleet_convergence/<run_id>/per_node_lag.json`. Per-node
fields:

| Field | Meaning |
|---|---|
| `node_id` | Stable id. |
| `latest_observed_quarantine_id` | Most recent quarantine decision the node has acknowledged. |
| `latest_published_quarantine_id` | Most recent decision the fleet's authoritative log holds. |
| `lag_decisions` | Difference (count of decisions the node has not yet acknowledged). |
| `lag_window_ms` | Wall-time difference between the latest-published and latest-observed timestamps. Compared against the SLO window. |
| `gossip_success_rate_millionths` | Fixed-point ratio over the most recent N gossip exchanges; below 500_000 (~50%) is a warning. |
| `last_successful_gossip_utc` | When the node last successfully exchanged with any neighbour. |

A single node lagging at high `gossip_success_rate` is usually a
backlog (the node will catch up). A low gossip success rate plus a
growing `lag_window_ms` is the signature of a real network issue.

## Diagnose vs partition decision tree

1. Read Layer 1. If `quorum_reached == true` AND `lagging_nodes` is
   empty, the fleet is healthy. STOP.
2. If `quorum_reached == true` AND `lagging_nodes` is non-empty,
   read Layer 3 for each lagging node. Most will be backlog
   (catching up); flag any whose `gossip_success_rate_millionths` is
   below the warning threshold for follow-up.
3. If `quorum_reached == false`, read Layer 2. Classify the partition
   into `Transient` / `Persistent` / `Permanent` and apply the
   per-class action.
4. If the partition is `Persistent` or `Permanent`, do NOT publish
   new quarantine decisions until the partition resolves. The
   convergence SLO is not provided under partition.

## The signed re-admission flow

Re-admission is the operator decision to lift a quarantine. It is
*new evidence*, not a rollback: the original quarantine decision
stays in the audit ledger and the re-admission record chains forward
from it.

### Step 1 — Identify the quarantine to lift

Pick the `quarantine_id` from the fleet's authoritative quarantine
log. Confirm:

- The quarantine is currently active (not already lifted).
- The quarantine's `security_epoch` is the current epoch (re-admission
  across epochs requires a separate cross-epoch ratchet review).
- The extension's behaviour has actually changed since the quarantine
  fired. Re-admission without a documented change is silent
  rollback dressed up as a procedure.

### Step 2 — Capture the operator's reasoning

Re-admission requires a written reason. The reason becomes part of
the signed record. Minimum content:

- Why the quarantine fired (the original `containment_reason`).
- What changed since (code fix, configuration change, false-positive
  determination, lattice re-tuning).
- What evidence supports the change (commit id, configuration diff,
  posterior-snapshot delta).
- Acceptance criteria for the re-admitted extension going forward
  (e.g. tighter resource budget, posterior tracking for N
  observations, snap-back-to-quarantine threshold).

### Step 3 — Capture the posterior snapshot at decision time

The Bayesian posterior the guardplane held over the extension's
risk state at the moment of the re-admission decision MUST be
attached to the signed record. Two reasons:

1. Audit can reconstruct exactly what the operator believed when
   making the decision.
2. If the re-admitted extension misbehaves again, the
   posterior-at-decision becomes the comparison baseline for "was
   this decision reasonable at the time?"

### Step 4 — Sign the re-admission receipt

The `ReAdmissionReceipt` is the canonical signed artifact. Fields:

| Field | Meaning |
|---|---|
| `re_admission_id` | UUIDv7. Cite this in any downstream operator action. |
| `quarantine_id` | The originating quarantine being lifted. Chain link. |
| `extension_id` | The extension being re-admitted. |
| `security_epoch` | Must match the current epoch. |
| `operator_identity` | The signed operator identity (Ed25519 verification key id + operator name). |
| `posterior_at_decision` | Canonical bytes of the guardplane posterior at the decision moment. |
| `reasoning` | The Step 2 reason text, canonicalised. |
| `acceptance_criteria` | The Step 2 acceptance criteria, structured. |
| `signature` | Ed25519 signature over the canonical bytes of all fields above. |
| `prev_hash` | Content hash of the originating quarantine decision. The chain link that prevents re-admission from being a silent rollback. |

The receipt MUST be signed by an operator key that the fleet's trust
root recognises. An unsigned re-admission is not a re-admission; it
is a request, and the fleet's enforcement layer refuses it.

### Step 5 — Publish + converge

Once signed, publish the re-admission receipt into the quarantine
ledger. The same convergence accountant that tracks quarantine
decisions tracks re-admission decisions. Wait for `quorum_reached`
again before declaring the re-admission propagated.

### Step 6 — Post-re-admission monitoring

The acceptance criteria from Step 2 are the live monitoring contract:

- If the criteria include "tighter resource budget", the orchestrator
  applies the tighter budget at re-admission time.
- If the criteria include "posterior tracking for N observations",
  the guardplane watches the extension for N observations and
  snap-backs to quarantine if the posterior crosses the declared
  threshold.
- Every observation against the re-admitted extension is logged with
  the `re_admission_id` so post-hoc audit can trace it back to the
  acceptance contract.

## Ratchet semantics — what NOT to do

The re-admission flow exists to preserve the ratchet: every
quarantine and every re-admission is evidence, both directions are
audited, and the audit trail is signed.

- **Do NOT** "unset" a quarantine in the ledger without producing a
  `ReAdmissionReceipt`. The ledger entry is immutable; the only
  legal way to disable a quarantine is to publish a re-admission
  receipt that chains forward from it.
- **Do NOT** re-admit across security epochs without a cross-epoch
  ratchet review. The quarantine's epoch is part of its identity;
  re-admitting across epochs is a separate operator surface.
- **Do NOT** sign a re-admission receipt with a service-account
  key. Re-admission is an operator decision, recorded against an
  operator identity. Service-account signatures are not operator
  identities even when their keys are technically valid.
- **Do NOT** publish a re-admission receipt while the fleet is
  partitioned (`quorum_reached == false`). The receipt will only
  reach one side of the partition and the two sides will hold
  divergent quarantine state until the partition resolves.
- **Do NOT** treat "extension was quarantined for a reason that
  turned out to be a false positive" as license to skip the
  reasoning + posterior + acceptance-criteria capture. A false
  positive lift IS new evidence and benefits from being recorded
  the same way as any other re-admission.

## Cross-cutting rules

- **Partition class first, then per-node lag.** A persistent
  partition makes per-node lag meaningless; resolve the partition
  before classifying individual lag entries.
- **Ratchet over rollback.** Every fleet-state change is forward-
  chained signed evidence. The runtime has no "undo".
- **Posterior snapshot is mandatory at decision time.** Capturing
  it post-hoc is reconstruction, not evidence.
- **Quorum threshold is policy, not constant.** Different deployment
  lanes set different `quorum_threshold_millionths`. Read the
  current value from `quorum_snapshot.json` rather than assuming
  the default (~2/3).

## Deferred (out of scope for this runbook)

The bead's full operator surface also names:

- `runbooks/scripts/fleet_diagnose.sh` — operator-readable wrapper
  that surfaces quorum state + partition detection + per-node lag
  with both plain-English output and structured JSON suitable for
  piping into frankentui.
- `runbooks/scripts/fleet_reauthorize_extension.sh` — implements the
  Step 1–6 re-admission flow as a guided script that captures
  operator identity + signed approval + posterior snapshot, then
  binds the result into a `ReAdmissionReceipt`.
- frankentui panel — fleet-convergence dashboard with per-node lag
  heatmap, partition-detection visualisation, re-admission approval
  workflow.
- ≥20 unit tests on the diagnose-script output parsing — pin the
  plain-English and JSON output shapes against regressions.

These are deferred because they depend on the convergence-accountant
JSON contract being stable; this runbook documents that contract so
the follow-up tooling can target a fixed shape. The deferred items
are tracked under the bd-cixqu.2.7 follow-up scope.

## Cross-references

- `crates/franken-engine/src/fleet_convergence.rs` — convergence
  accountant.
- `crates/franken-engine/src/quarantine_mesh_gate.rs` — per-node
  enforcement.
- `crates/franken-engine/src/quarantine_propagation.rs` — gossip
  propagation.
- `crates/franken-engine/src/fleet_immune_protocol.rs` — fleet-
  immune contract.
- [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md) —
  broader gate catalogue.
- Sibling operator runbooks
  ([`ADDING_A_NEW_CAPABILITY.md`](./ADDING_A_NEW_CAPABILITY.md),
  [`INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`](./INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md),
  [`FORMAL_METHODS_WORKFLOW.md`](./FORMAL_METHODS_WORKFLOW.md),
  [`CROSS_PLATFORM_INCIDENT_TRIAGE.md`](./CROSS_PLATFORM_INCIDENT_TRIAGE.md),
  [`COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md`](./COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md),
  [`LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`](./LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md),
  [`PRIVACY_BUDGET_AND_POSTERIOR_AGGREGATION_TRIAGE.md`](./PRIVACY_BUDGET_AND_POSTERIOR_AGGREGATION_TRIAGE.md),
  [`COMPOUNDING_GENERATOR_REVIEW_SURFACE.md`](./COMPOUNDING_GENERATOR_REVIEW_SURFACE.md)).
