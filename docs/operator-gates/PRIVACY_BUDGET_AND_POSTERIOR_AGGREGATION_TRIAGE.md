# Privacy Budget Tracking + Posterior Aggregation Triage

Operator runbook for the FrankenEngine differential-privacy budget
accountant and federated posterior aggregator. Covers how to read the
ε,δ remaining counters, when to refuse new aggregations, and how to
audit per-node contribution to a published aggregate.

## Bead anchors

- Track parent: **bd-cixqu.20** (Track T — privacy-preserving fleet
  learning: federated posterior + differential privacy).
- This document: **bd-cixqu.20.6** (T.6 operator-runbook).
- Engine surface: `crates/franken-engine/src/dp_budget_accountant.rs`
  (the live `EpochBudget` + `LifetimeBudget` accountant with
  `epsilon_budget_millionths`, `epsilon_spent_millionths`,
  `would_exhaust(epsilon, delta)`, and the `Aggregation` /
  `AggregationDecision` types).
- Supporting modules:
  `crates/franken-engine/src/privacy_learning_contract.rs` (the
  federated posterior contract — what shape an admissible aggregation
  must have).
- Sibling runbooks (same diagnose / decide / act / verify pattern):
  [`COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md`](./COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md),
  [`LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`](./LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md),
  [`INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`](./INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md).

## Why this surface exists

FrankenEngine's fleet-learning lane lets the runtime aggregate
posterior beliefs across many nodes without seeing any individual
node's data clear. The privacy guarantee depends on **two finite
budgets**: per-epoch ε,δ (the fleet learns at most `ε_epoch` worth of
information about any one node per epoch) and lifetime ε,δ (the fleet
learns at most `ε_lifetime` total). Once a budget is exhausted, no
further aggregations against the same node may be admitted — doing so
breaks the privacy contract.

The accountant tracks both budgets in fixed-point millionths
(`epsilon_budget_millionths`, `epsilon_spent_millionths`,
`epsilon_remaining_millionths`) consistent with the project's
determinism discipline (no f64 in hashed positions).

## Interpreting ε, δ remaining

The accountant exposes two scalar pairs:

| Field | Meaning |
|---|---|
| `epoch_epsilon_remaining_millionths` | ε remaining in the current epoch. Resets at each epoch transition. Fixed-point millionths (`1_000_000 = 1.0`). |
| `epoch_delta_remaining_millionths` | δ remaining in the current epoch. Same units. |
| `lifetime_epsilon_remaining_millionths` | ε remaining across the node's lifetime. **Does not reset.** Once spent, stays spent. |
| `lifetime_delta_remaining_millionths` | δ remaining across the node's lifetime. **Does not reset.** |

Read both pairs together. An aggregation against a node is admissible
only when the requested (ε, δ) cost fits inside BOTH the epoch
remainder AND the lifetime remainder. The accountant's
`would_exhaust(epsilon, delta)` method does this check — call it
before queueing any new aggregation, not after.

### Interpretation thresholds (operator guidance)

| Remaining (epoch OR lifetime) | Posture | Action |
|---|---|---|
| `>= 250_000 millionths` (≥0.25) | Healthy | Accept new aggregations against this node normally. |
| `100_000 – 250_000` (0.10–0.25) | Cautious | Accept new aggregations only when the requested (ε, δ) is below `0.05` (fixed-point `50_000`). Larger requests must escalate to operator review. |
| `10_000 – 100_000` (0.01–0.10) | Constrained | Accept only "must-publish" aggregations (those covered by an external claim that names this node). Refuse opportunistic learning queries. |
| `0 – 10_000` (≤0.01) | Exhausted-soon | Refuse all new aggregations except a final "summary publish" if one is queued and budgeted. |
| `0` (or `would_exhaust` returns `true` for the proposed cost) | Exhausted | Refuse. The accountant's fail-closed branch is the canonical response. |

The thresholds are operator-defaults, not mathematical truths. The
**only** mathematical rule the accountant enforces is "do not admit
an aggregation whose cost > remaining." The thresholds above are
about giving the operator a smooth-degradation curve before the wall
hits.

## When to refuse new aggregations

Refuse (return `AggregationDecision::Refused`) when any of the
following is true. These are listed in the order the engine itself
checks; the runbook mirrors the engine's fail-closed sequence so the
operator-facing rule matches the runtime rule exactly.

1. **`would_exhaust` returns `true`.** The proposed (ε, δ) cost
   exceeds the remaining budget on either the epoch or lifetime
   accountant. Non-negotiable; the accountant rejects regardless of
   operator preference.
2. **Epoch mismatch.** The aggregation request carries an epoch
   identifier that does not match the accountant's current epoch.
   This usually means a request was queued during an epoch transition
   — re-issue the request bound to the current epoch.
3. **Sensitivity overrun.** The aggregation declares a per-sample
   sensitivity larger than the contract's declared maximum. The
   accountant cannot certify the ε,δ cost if the sensitivity is
   unbounded.
4. **Node revoked from learning lane.** The node's
   `PrivacyLearningParticipation` flag is `revoked` (see
   `privacy_learning_contract.rs`). Refuse regardless of remaining
   budget.
5. **Composition limit reached.** Even if `epsilon_remaining` looks
   non-zero, the composed-epsilon counter (`composed_epsilon_millionths`)
   accounts for sequential composition's tighter bound and may already
   indicate exhaustion under the chosen composition theorem (basic
   vs advanced). Trust `would_exhaust` over the raw remaining value.

A refusal is itself an event the accountant emits. Read it as a
positive signal, not a failure: the accountant did its job. The
remediation is to either widen the budget (a policy change requiring
operator approval) or to forgo the aggregation.

## How to audit per-node contribution to a published aggregate

When the fleet publishes an aggregate posterior, every node that
contributed signs a receipt naming its individual ε,δ cost. The
audit trail is the contribution-receipt ledger; the runbook tells the
operator how to read it.

### Audit step 1 — Find the contribution-receipt ledger entry

Each published aggregate has a `published_aggregate_id`. The
contribution-receipt ledger (`artifacts/dp_aggregation/ledger.jsonl`
or the operator-specified path) holds one record per `(node_id,
published_aggregate_id)` pair:

| Field | Meaning |
|---|---|
| `node_id` | Stable id of the contributing node. |
| `published_aggregate_id` | The aggregate this contribution feeds. |
| `epoch_id` | Epoch at the moment of contribution. |
| `epsilon_consumed_millionths` | The ε this node spent on this aggregation. |
| `delta_consumed_millionths` | The δ this node spent. |
| `composition_theorem` | `Basic` or `Advanced` — which composition rule the accountant used to derive the consumed total. |
| `sensitivity_bound_millionths` | Per-sample sensitivity at the moment of contribution. |
| `signature` | Ed25519 signature over the canonical bytes of the receipt. |
| `prev_hash` | Chain link to the previous contribution receipt in the ledger. |

The `prev_hash` chain makes any retroactive edit detectable. An audit
that finds an entry whose `prev_hash` does not match the previous
entry's content hash has discovered ledger tampering and must
escalate (do not proceed with the audit; the trail is no longer
trustworthy).

### Audit step 2 — Verify the aggregate's cost decomposition

For a given `published_aggregate_id`, sum
`epsilon_consumed_millionths` across all contributing nodes. The sum
must match the aggregate's declared `composed_epsilon_millionths`
under the chosen `composition_theorem`. A mismatch means either:

- The composition theorem is wrong (the engine declared `Basic` but
  the contribution shape requires `Advanced`, or vice versa), or
- A contribution receipt is missing (the ledger is incomplete), or
- A contribution receipt was forged (the signature is bad).

The accountant's own audit tool (`scripts/audit_dp_aggregation_ledger.sh`
under the runbook's expected sibling artifacts) performs this
verification; the operator runs it as part of any published-aggregate
review.

### Audit step 3 — Cross-check against the lifetime ledger

For each `node_id` that contributed, sum
`epsilon_consumed_millionths` across all aggregations EVER for that
node. The sum must be `<= lifetime_epsilon_budget_millionths`. A node
whose lifetime sum exceeds the budget has been over-charged — this is
either a budget-policy bug (the lifetime budget was widened
mid-stream without signed approval) or an accountant bug (the
accountant admitted an aggregation it should have refused).

The lifetime-sum cross-check is the most expensive audit step but the
most important: it catches errors the single-aggregate verification
(Step 2) cannot see.

### Audit step 4 — Verify ledger signatures

For each contribution receipt, verify the Ed25519 signature against
the node's published verification key. Receipts with invalid
signatures are evidence of either ledger tampering or a compromised
node signing key. Escalate both cases.

## Cross-cutting rules

- **Trust the accountant, not the raw remaining counter.**
  `would_exhaust(epsilon, delta)` accounts for composition;
  `epsilon_remaining_millionths` does not. Reading the raw counter
  and concluding "we have budget" can lead to over-spend under
  sequential composition.
- **Fixed-point millionths, never f64.** Per the project's
  determinism discipline, every ε,δ field in the accountant is
  `i64` in millionths. An operator-facing report that converts these
  to floats for display is fine; an audit that re-derives totals
  must work in millionths throughout.
- **Refusal is not an error.** A refused aggregation is the
  accountant working as designed. Treat it as a signal, not a
  symptom.
- **Budgets are per-node, not per-aggregate.** A single aggregate
  can consume budget against many nodes; each node's accountant
  decides independently whether to admit.
- **Lifetime budget does not reset.** No operator action can restore
  spent lifetime budget. The only escape is a signed budget-widening
  policy change, which is a separate review surface.

## What NOT to do

- **Do not** widen the lifetime budget silently to admit an
  aggregation that `would_exhaust` refused. The lifetime budget IS
  the privacy guarantee; widening it without a signed policy change
  amounts to retroactively weakening every previously-published claim
  that relied on the old budget.
- **Do not** treat a single-aggregate verification (Step 2 alone) as
  a full audit. Step 3 (lifetime cross-check) is what catches the
  accountant-bug class of failure.
- **Do not** suppress refused-aggregation events from the report. The
  refusal record IS evidence the accountant did its job; suppressing
  it removes the audit trail of fail-closed behaviour.
- **Do not** publish an aggregate whose per-node ε,δ sum does not
  decompose under the declared composition theorem. The mismatch IS
  the error; publishing past it locks in the wrong privacy claim.

## Deferred (out of scope for this runbook)

The bead's full operator surface also names a `frankentui` privacy-
budget dashboard (per-node remaining heatmap + ledger-chain visualiser
+ refusal-stream queue) and the audit-script wrapper
`scripts/audit_dp_aggregation_ledger.sh`. These are deferred because
they depend on the typed evidence atom emitter contract being stable
first; this runbook documents the contract so the follow-ups can
target a fixed shape.

## Cross-references

- `crates/franken-engine/src/dp_budget_accountant.rs` —
  `EpochBudget`, `LifetimeBudget`, `would_exhaust`, the canonical
  ε,δ counters in millionths.
- `crates/franken-engine/src/privacy_learning_contract.rs` —
  `PrivacyLearningParticipation`, composition-theorem selection,
  contribution-receipt shape.
- [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md) —
  broader gate catalogue (the DP accountant exposes its own gate
  there).
- [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md) —
  the matrix row that names this surface for FE-CLAIM-021 (or
  successor — check the latest matrix entry).
- Sibling operator runbooks (`ADDING_A_NEW_CAPABILITY.md`,
  `INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`,
  `FORMAL_METHODS_WORKFLOW.md`,
  `CROSS_PLATFORM_INCIDENT_TRIAGE.md`,
  `COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md`,
  `LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`).
