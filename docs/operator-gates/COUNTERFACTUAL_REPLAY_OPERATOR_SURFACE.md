# Counterfactual Replay Operator Surface

Operator runbook for launching counterfactual replays, interpreting
per-node deltas, and using counterfactual evidence in incident
retrospectives.

## What a counterfactual replay is

A counterfactual replay takes a real trace (the observed routing /
fallback / control decisions a fleet of nodes produced under policy
P_actual) and re-simulates the same trace inputs under an alternate
policy P_counterfactual. The engine then computes, per node, the
outcome delta between actual and counterfactual: what the node would
have done, what evidence it would have emitted, and what containment
action would have fired.

The point is forensic, not aspirational: a counterfactual replay
answers "what would have happened if the policy had been X at the
moment Y fired?". It is not a planning tool; it produces evidence for
review, not commands for live mutation.

## Bead anchors

- Track parent: **bd-cixqu.19** (FRX-19 / FE-CLAIM-021 — counterfactual
  fleet replay across multiple policy snapshots).
- This document: **bd-cixqu.19.6** (S.6 operator-runbook).
- Engine surface: `crates/franken-engine/src/counterfactual_replay_engine.rs`.
- Supporting modules: `causal_replay.rs` (trace record + config),
  `counterfactual_evaluator.rs` (ConfidenceEnvelope + EnvelopeStatus +
  EstimatorKind), `structural_causal_model.rs` (CausalEffect, SCM).
- Companion runbook for the forensic-replay side:
  [`FORMAL_METHODS_WORKFLOW.md`](./FORMAL_METHODS_WORKFLOW.md) for the
  proof-bundle reading order (counterfactual reports live in the same
  bundle shape).

## How to launch a counterfactual

The minimum input shape:

| Required | What to provide |
|---|---|
| Captured trace | A `TraceRecord` from a real fleet run — captured via the live trace recorder; the source-of-truth for what *actually* happened. |
| Actual policy snapshot | The `PolicyId` (content hash) of the policy that produced the trace. The engine resolves this against the policy ledger to recover the full policy bytes. |
| Counterfactual policy snapshot | The `PolicyId` of the alternate policy you want to compare against. Must already exist in the policy ledger — the engine refuses to replay against a policy it cannot reproduce. |
| Confidence envelope | A `ConfidenceEnvelope` declaring the tolerance band for the delta. The engine refuses to publish a counterfactual whose envelope is wider than the policy-comparison contract allows. |
| Security epoch | The `SecurityEpoch` the original trace ran under. Mismatched epochs trigger fail-closed before any simulation runs. |

Launch (single-policy comparison):

```bash
frankenctl counterfactual replay \
    --trace <captured_trace.json> \
    --actual-policy <policy_id_actual> \
    --counterfactual-policy <policy_id_alternate> \
    --envelope <confidence_envelope.json> \
    --security-epoch <epoch_id> \
    --out artifacts/counterfactual_replay/<run_id>/
```

For a many-policy sweep (the canonical Track S use case — comparing
the actual policy against every snapshot since the last release), use
`--counterfactual-policies` with a manifest listing the snapshots to
sweep. The engine emits one comparison artifact per policy.

The engine refuses (fail-closed) to launch when:
- The trace's recorded policy id does not match `--actual-policy`.
- The counterfactual policy is at a security epoch ≠ the trace's epoch.
- The confidence envelope is `EnvelopeStatus::Open` (an open envelope
  has no upper bound and produces unpublishable deltas).
- The captured trace is missing any `DecisionSnapshot` for a node
  whose decision the counterfactual policy would also evaluate.

## How to interpret per-node deltas

Each comparison artifact contains a `CounterfactualDelta` record per
node in the trace:

| Field | Meaning |
|---|---|
| `node_id` | Stable id of the fleet node. |
| `actual_action` | The `LaneAction` (`Allow / Challenge / Sandbox / Suspend / Terminate / Quarantine`) the node produced under the actual policy. |
| `counterfactual_action` | The `LaneAction` the node would have produced under the alternate policy. |
| `delta_kind` | One of `Identical / Tightened / Loosened / Class-Shifted / Inverted` (see classification below). |
| `evidence_delta` | The change in emitted evidence — what the alternate policy would have signed differently. |
| `causal_effect` | Per-node `CausalEffect` from the structural causal model, naming which input variables drove the divergence. |
| `confidence_envelope` | The per-node tolerance band: tightening below this band is rounding noise, widening past it is a real divergence. |
| `estimator_kind` | The `EstimatorKind` used to compute the delta (`PointEstimate`, `BoundedInterval`, `BootstrappedMean`, etc.). |

### Reading order

1. **Filter by `delta_kind`**. A run where 99% of nodes are `Identical`
   is dominated by the 1% that diverged — read those first.
2. **For each non-`Identical` node, read `causal_effect` before
   `actual_action`**. The causal effect names the input variable
   responsible for the divergence; that is the lever the alternate
   policy would have pulled. The `actual_action` / `counterfactual_action`
   pair tells you what the change of policy bought you operationally;
   it does not tell you why.
3. **Check `confidence_envelope.status` per node**. A `Closed` envelope
   means the delta is publishable. A `Bounded` envelope means the
   delta is inside the published tolerance — operationally identical.
   A `Open` envelope is a soft failure: the engine could not confidently
   measure the delta, so do not act on the comparison for that node.

### Delta-kind classification

| `delta_kind` | What it means | Action |
|---|---|---|
| `Identical` | Same `LaneAction`, same evidence shape. | Nothing — the alternate policy would have been a no-op for this node. |
| `Tightened` | Counterfactual is strictly more conservative (e.g. `Sandbox` → `Suspend`). | If you are evaluating a "would we have caught attack X earlier" hypothesis, tightened nodes are the evidence for "yes". |
| `Loosened` | Counterfactual is strictly more permissive (e.g. `Quarantine` → `Sandbox`). | Risk of false-negative regression. Only acceptable if the original action's evidence shows the original was a false-positive. |
| `Class-Shifted` | The two actions are in different containment classes (e.g. `Challenge` ↔ `Sandbox`) and not strictly comparable. | Read both pieces of evidence; class shifts are usually a sign the policy boundaries themselves changed shape. |
| `Inverted` | The two actions are operationally opposite (e.g. `Allow` ↔ `Quarantine`). | Highest scrutiny. Inverted nodes usually indicate the alternate policy is operating on a different model of the threat. Cite the `causal_effect` field when escalating. |

## Using counterfactuals in incident retrospectives

Counterfactual replay is the strongest evidence shape an incident
retrospective can carry, because the comparison policy is named, the
trace is real, and the delta is signed.

A retrospective workflow:

### Step 1 — Capture the actual trace

The trace must be the same byte-identical artifact the incident
generated. If the trace is reconstructed from logs, it is not eligible
for counterfactual replay (logs are not signed, traces are).

### Step 2 — Identify the candidate alternate policies

For each candidate policy you want to compare against, confirm:
- The policy is in the policy ledger (`PolicyId` resolves).
- The policy snapshot's security epoch matches the trace's epoch.
- The policy was a real candidate at the time — comparing against a
  policy that did not exist when the incident happened produces a
  hypothesis, not a counterfactual.

### Step 3 — Run the comparison

Launch via the CLI above with the candidate policies as a
`--counterfactual-policies` manifest. The engine emits one comparison
artifact per policy; sweep them as a set.

### Step 4 — Read the deltas

Walk the comparison artifacts in `delta_kind` priority order:
`Inverted` → `Tightened` (if the retrospective is asking "would we
have caught this earlier") → `Loosened` (if asking "would we have
over-reacted") → `Class-Shifted` (if asking "did the policy boundary
shift") → `Identical` (only as a noise floor — should be the vast
majority of nodes for a sensible candidate policy).

### Step 5 — Anchor the retrospective claim

Each retrospective claim ("policy X would have caught the attack at
node Y three minutes earlier") must cite:
- The trace artifact (content hash).
- The actual policy (`PolicyId`).
- The counterfactual policy (`PolicyId`).
- The specific `CounterfactualDelta` record (node_id + delta_kind).
- The confidence envelope state for that node.

A retrospective that cites only the conclusion without the trace +
both policies + the delta record is **not** counterfactual evidence —
it is operator narrative. The `claim-to-proof matrix` gate refuses
retrospective claims whose backing is not anchored to a signed
counterfactual comparison artifact.

## What NOT to do

- **Do not** launch a counterfactual against a policy you intend to
  promote. The CLI's job is forensic. Policy promotion is a separate
  workflow with its own gates (the proof-rebuild path under
  [`FORMAL_METHODS_WORKFLOW.md`](./FORMAL_METHODS_WORKFLOW.md)).
- **Do not** treat an `Open` confidence envelope as a delta. An open
  envelope is the engine's "I could not measure this confidently"
  signal; using it as evidence misrepresents what the comparison
  established.
- **Do not** average per-node deltas across the fleet to produce a
  single fleet-level "would have been X% better" number without
  signing the underlying per-node deltas separately. Aggregated
  numbers without per-node anchors are not retrospective evidence.
- **Do not** replay against a different security epoch than the trace.
  The engine refuses, but if a future automation chains policies in
  some way, the operator-facing rule is the same: cross-epoch
  comparison is not a counterfactual; it is a different question.

## Cross-references

- `crates/franken-engine/src/counterfactual_replay_engine.rs` — engine
  entry point + delta types.
- `crates/franken-engine/src/counterfactual_evaluator.rs` —
  `ConfidenceEnvelope`, `EnvelopeStatus`, `EstimatorKind` definitions.
- `crates/franken-engine/src/causal_replay.rs` — trace record and
  config types the CLI binds.
- `crates/franken-engine/src/structural_causal_model.rs` —
  `CausalEffect` / SCM that powers the per-node causal attribution.
- [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md)
  — broader gate catalogue.
- [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md) —
  the claim-anchoring rule retrospectives must satisfy.
- Sibling operator runbooks (`ADDING_A_NEW_CAPABILITY.md`,
  `INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`,
  `FORMAL_METHODS_WORKFLOW.md`,
  `CROSS_PLATFORM_INCIDENT_TRIAGE.md`) — same diagnose/decide/act/verify
  pattern.
