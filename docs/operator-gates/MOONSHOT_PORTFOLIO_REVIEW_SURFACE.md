# Moonshot Portfolio Review Surface

Operator runbook for consuming the Track W ranked-portfolio report
(`bd-cixqu.23.2`), accepting / overriding / rejecting its
recommendations, and retiring a moonshot from the active list. The
underlying scoring engine is documented as a contract here so that the
follow-up review-surface CLI / TUI panel can target a fixed shape
rather than a moving one.

## Bead anchors

- Track parent: **bd-cixqu.23** (Track W — submodular moonshot
  portfolio governor; sharpened in Track LL).
- This document: **bd-cixqu.23.3** (W.3 operator-runbook).
- Dependencies:
  - bd-cixqu.23.1 (W.1) — expected-info-value scoring across active
    moonshots (the per-bead score the report sorts by).
  - bd-cixqu.23.2 (W.2) — weekly ranked report (the artifact this
    runbook teaches operators to read).
- Engine surface:
  - `crates/franken-engine/src/portfolio_governor.rs` — `Scorecard`,
    `PortfolioGovernor`, `GovernorDecision`, `GovernorDecisionKind`,
    `GovernorConfig`, `MoonshotState`, `MoonshotStatus`.
  - `crates/franken-engine/src/moonshot_contract.rs` —
    `MoonshotContract`, `MoonshotStage`, `KillCriterion`,
    `RollbackPlan`, `EvModel`, `RiskBudget`.
  - `crates/franken-engine/src/moonshot_disruption_track.rs` —
    frontier-release gate (`allows_frontier_release` /
    `execute_disruption_track`); a separately-gated promotion path
    referenced when a moonshot reaches frontier candidacy.
- Sibling runbooks:
  - [`FORMAL_METHODS_WORKFLOW.md`](./FORMAL_METHODS_WORKFLOW.md) —
    Lean 4 proof rebuild (a Track G moonshot interacts here when its
    proof carriers shift confidence on a W scorecard).
  - [`COMPOUNDING_GENERATOR_REVIEW_SURFACE.md`](./COMPOUNDING_GENERATOR_REVIEW_SURFACE.md)
    — Track U attack-class review surface (sibling
    "operator-facing-report → decision" runbook with the same
    diagnose / decide / act / verify pattern; different domain).

## What the W.2 ranked report is

The report is produced by
`PortfolioGovernor::rank_portfolio(now_ns) -> Vec<(moonshot_id, score)>`.
Each entry's `score` is the value returned by
`Scorecard::risk_adjusted_ev()` for the most recent scorecard. The
sort is descending; higher score means "invest next".

The score is computed (in millionths, with i128 intermediates) as:

```text
risk_adjusted_ev =
      ev * confidence / 1_000_000
    - risk_of_harm * 2
    - cross_initiative_interference
    - implementation_friction
    - operational_burden
```

Every term is in millionths (1_000_000 = 1.0). The `i64` result can be
negative — a negative-score moonshot is one the governor would not
promote at this instant.

## The scorecard fields, in the order to read them

Every entry in the W.2 report can be expanded to its underlying
`Scorecard`. Read the fields in this order:

| # | Field (millionths) | What it tells you | Operator question this resolves |
|---|---|---|---|
| 1 | `confidence_millionths` | How sure the model is in its EV estimate (0..1_000_000). | "Should I trust the rest of this row?" Below `GovernorConfig::hold_confidence_below_millionths` (default **500_000**) the governor will not promote at all — it issues a `Hold`. |
| 2 | `ev_millionths` | Point-estimate of expected value if the moonshot succeeds (signed i64). | "Is this worth running?" A high `ev` with low `confidence` means the upside is large but the model has not yet earned the right to bet on it. |
| 3 | `risk_of_harm_millionths` | Probability of net-negative outcome (0..1_000_000). | "Could this make things worse?" Multiplied by 2 in the score formula — risk is weighted heavier than the other penalties. Above `GovernorConfig::promotion_risk_threshold_millionths` (default **200_000**) the governor will not promote. |
| 4 | `cross_initiative_interference_millionths` | Estimated drag this moonshot puts on other active moonshots. | "Is this fighting another active bet for the same surface?" High interference is the most common reason a high-EV moonshot ranks below a lower-EV one. |
| 5 | `implementation_friction_millionths` | Estimated effort overhead beyond the stated contract. | "Is the team going to bleed on this?" A high-friction high-EV moonshot is a candidate for `Pause` (re-allocate resources) rather than `Kill`. |
| 6 | `operational_burden_millionths` | Estimated post-ship operational cost (paging, oncall, audit traffic). | "Will this become someone's permanent problem?" This is the most commonly underweighted term in early-stage reports. |
| 7 | `risk_adjusted_ev()` | The final sort key. | "Where on the list is this row?" Read it last — reading it first invites confirmation bias. |

`computed_at_ns` and `epoch` round-trip back into the audit trail.
Cite both when filing an override decision.

## How to read a single row

Each ranked-report row carries:

- `moonshot_id` — the join key to `MoonshotContract::moonshot_id`.
- `score` — `risk_adjusted_ev()` from the most recent `Scorecard`.
- `recommended_action` — derived by the report builder from the
  governor's per-moonshot evaluation. One of:
  - `Promote { from, to }` — confidence ≥ promote threshold AND risk
    ≤ promote threshold AND stage obligations met.
  - `Hold { reason }` — confidence < hold threshold OR insufficient
    artifacts for the next stage.
  - `Kill { triggered_criteria }` — at least one
    `MoonshotContract::kill_criteria` predicate fired.
  - `Pause { reason }` — explicit operator-or-governor decision to
    free resources; the moonshot is preserved but not advanced.
  - `Resume` — only valid if the prior status was `Paused`.

The recommended action is a **proposal**. Operator approval (or
override) records a signed `GovernorDecision` into the governance
audit ledger (`portfolio_governor.rs:316` —
`enable_governance_audit_ledger`).

## Decision tree: accept, override, or retire

1. **Confirm the row is reproducible.** Re-run the governor against
   the same `epoch` + `now_ns` from the report header; the score must
   match exactly (deterministic fixed-point math). A score that
   shifts across re-runs at the same epoch is a Track-W contract
   violation — file an engine bead, do NOT act on the row.

2. **Read in the order above (fields 1 → 7).** If your reading of
   fields 1–6 conflicts with the recommended action, the override
   path (step 4) applies. If it agrees, jump to step 3.

3. **Accept the recommendation.** Call the matching
   `PortfolioGovernor::*` method:
   - Promote: `evaluate_gate(moonshot_id, now_ns)` — the
     decision lands as a `Promote` `GovernorDecision`.
   - Hold: no action required; the report will re-surface next
     cadence (`GovernorConfig::scoring_cadence_ns`, default 7 days).
   - Kill: `check_kill_criteria(moonshot_id, now_ns)` — the decision
     lands as `Kill { triggered_criteria }` and the moonshot moves to
     `MoonshotStatus::Killed`.
   - Pause: `pause_moonshot(moonshot_id, reason, now_ns)`.
   - Resume: `resume_moonshot(moonshot_id, now_ns)`.

4. **Override the recommendation.** Operator override is a
   first-class operation; it is NOT a manual fixup. The override
   surface MUST produce a `GovernorDecision` of its own, with:
   - `decision_id` (UUIDv7) — the join key for any subsequent
     ledger entry, audit query, or post-mortem.
   - `moonshot_id` — the row being overridden.
   - `kind` — the action the operator chose (e.g., `Hold` when the
     governor recommended `Promote`).
   - `scorecard` — the scorecard the override was made against
     (copied verbatim from the report so the override is anchored to
     the evidence the operator actually saw).
   - `timestamp_ns` + `epoch` — both copied from the report header.
   - `rationale` — a non-empty operator-written explanation. An
     override with empty rationale must be rejected at the review
     surface; do not silently default it.
   The override receipt is signed and appended to the governance
   audit ledger. Subsequent W.2 reports surface the override
   alongside the governor's recommendation so future operators can
   see the divergence and its rationale.

5. **Retire a moonshot from the active list.** Retirement is a
   permanent transition. Use it when:
   - The moonshot reached `MoonshotStatus::Completed` (success path).
     The portfolio governor stops scoring it; the contract remains in
     the audit ledger.
   - The moonshot was `Killed` and the rollback plan
     (`MoonshotContract::rollback_plan`) has executed successfully —
     each `RollbackStep` recorded and acknowledged. Until rollback
     completes, the killed moonshot remains in the active list as
     "Killed, rollback pending" and must NOT be retired.
   - The moonshot's epoch is older than the current
     `PortfolioGovernor::epoch` AND the contract carries no live
     rollback obligations. Stale-epoch moonshots can be retired
     without rollback because their state has already been rotated
     out by the epoch transition.
   Retirement itself is NOT performed by the runbook surface; it is
   performed via a separate, signed retirement transaction that
   produces a final `GovernorDecision` of kind `Kill` (with rationale
   `"retired: <reason>"`) followed by a `governance_audit_ledger`
   close-out entry. The retirement transaction is deferred (see
   "Deferred scope" below) but the contract above is what the
   transaction must satisfy.

## When the governor recommendation is wrong

The recommendation is wrong (and the override path is the correct
action) when ONE of these conditions holds:

- **Confidence is high but the model has not seen the failure mode
  you're worried about.** A scorecard with `confidence ≥ 0.75` can
  still miss a categorical risk that wasn't in the EV model's input
  features. If the operator can name the unmodeled risk, the
  override is justified — record the risk in the rationale so the
  W.1 scorer can incorporate it in the next pass.
- **The cross-initiative interference penalty was computed against
  an older portfolio snapshot.** If a new conflicting moonshot
  registered after the report was generated, the
  `cross_initiative_interference_millionths` is stale. Re-run the
  governor before promoting; if not feasible, override to `Hold` and
  cite the new conflicting moonshot in the rationale.
- **A `KillCriterion` is logically met but the runtime hasn't yet
  observed the metric.** If the operator has out-of-band evidence
  that a kill condition is true (a downstream incident, a sibling
  service alert), override to `Kill` and record the out-of-band
  evidence pointer in the rationale.
- **The recommended action conflicts with a frontier-release gate
  result.** If `moonshot_disruption_track::allows_frontier_release`
  is false for this moonshot, the W.2 recommendation cannot be
  `Promote` past the frontier stage even if the score would allow
  it. The two gates compose — both must agree.

When NONE of those conditions hold, the recommendation is correct;
do not override.

## What NOT to do

- **Do NOT promote a moonshot whose `Scorecard::confidence_millionths`
  is below `GovernorConfig::hold_confidence_below_millionths`.**
  Doing so bypasses the hold-gate; the audit ledger will surface the
  override forever. Use `Hold` and wait for the next cadence.
- **Do NOT pause a `Killed` moonshot to "park it for review".**
  `Pause` is a state for live moonshots awaiting resource
  reallocation; `Killed` is terminal. Reviving a killed moonshot
  requires a new `MoonshotContract` (and a new contract id).
- **Do NOT retire a `Killed` moonshot whose rollback steps are
  incomplete.** The rollback ledger is the only mechanism that
  guarantees the moonshot's side-effects are undone. Retire-before-
  rollback leaves stranded state and breaks the audit trail.
- **Do NOT override without a non-empty `rationale`.** An override
  receipt with empty rationale defeats the entire point of having a
  signed override surface; reject the submission at the review tool
  rather than persisting it.
- **Do NOT edit a prior `GovernorDecision` to "fix" its rationale.**
  The ledger is append-only. To correct a misfiled rationale, file a
  new decision of kind `Resume` (or whatever the no-op transition
  is) with rationale `"corrects decision_id=<prior>; see body"` and
  cite the original.
- **Do NOT consume the W.2 ranked-portfolio report in a tool that
  does not display the underlying scorecard.** The score alone is
  not enough to decide; the seven fields above are the actual
  evidence. A review tool that shows only the score is a foot-gun.

## Cross-cutting rules

- **The scorecard is the evidence, not the rank.** Sort order is a
  convenience; every decision must cite the underlying scorecard
  fields.
- **The audit ledger is the source of truth.** The governor's
  in-memory `decisions: Vec<GovernorDecision>` is rebuilt from the
  ledger on restart; if a decision is not in the ledger, it did not
  happen.
- **Determinism is contract.** The governor is deterministic given
  (epoch, now_ns, metric_history, completed_artifacts). Any
  non-determinism observed in the review surface is a bug, not a
  judgement call.
- **The override surface is part of the audit trail.** Every
  override receipt is signed; the signature key is bound to the
  operator identity recorded in the ledger.

## Deferred (out of scope for this runbook)

The W.3 review surface is implemented incrementally. The following
artifacts are explicitly deferred to follow-up beads under
bd-cixqu.23, parented by the JSON contract this runbook stabilizes:

- A `runbooks/scripts/review_moonshot_portfolio.sh` wrapper that
  reads a W.2 report (JSON), walks the operator through each row
  via prompt, and emits a batch of signed `GovernorDecision`
  receipts.
- A `runbooks/scripts/retire_moonshot.sh` wrapper that performs the
  retirement transaction described above — verifies status,
  rollback completion, and epoch age before producing the close-out
  decision.
- A frankentui panel for the moonshot portfolio surface (sortable
  rank table + per-row scorecard expansion + override modal +
  history-of-decisions tab per moonshot).
- A "diff against previous cadence" view that highlights moonshots
  whose score crossed a promote / hold / kill threshold since the
  last W.2 report. The contract for this diff lives at
  `Scorecard::computed_at_ns` + `epoch` — two consecutive scorecards
  for the same `moonshot_id` define the diff.
- The `GovernorDecision`-signing key management UX (key rotation,
  per-operator key issuance). The cryptographic primitives are
  already in the engine; the operator-facing surface is deferred.

Landing these follow-ups against the contract above lets each target
a fixed shape rather than a moving one. None of them are blockers
for the runbook itself: the contract is what stabilizes the surface,
not the tooling.

## Cross-references

- `crates/franken-engine/src/portfolio_governor.rs` — `Scorecard`,
  `PortfolioGovernor::rank_portfolio`, `evaluate_gate`,
  `check_kill_criteria`, `pause_moonshot`, `resume_moonshot`,
  `GovernorDecision`, `GovernorDecisionKind`, `GovernorConfig`,
  `MoonshotState`, `MoonshotStatus`.
- `crates/franken-engine/src/moonshot_contract.rs` —
  `MoonshotContract`, `MoonshotStage`, `KillCriterion`,
  `RollbackPlan`, `EvModel`, `RiskBudget`.
- `crates/franken-engine/src/moonshot_disruption_track.rs` —
  `allows_frontier_release`, `execute_disruption_track` (composes
  with W.2 recommendations at the frontier stage).
- `crates/franken-engine/src/governance_audit_ledger.rs` (under
  `portfolio_governor/`) — the append-only ledger that backs the
  signed override receipts.
- [`COMPOUNDING_GENERATOR_REVIEW_SURFACE.md`](./COMPOUNDING_GENERATOR_REVIEW_SURFACE.md)
  — sibling operator-facing-report → decision runbook (different
  domain, same diagnose / decide / act / verify pattern).
- [`FORMAL_METHODS_WORKFLOW.md`](./FORMAL_METHODS_WORKFLOW.md) —
  Track G proof-carrier workflow; Track G moonshots interact with
  the W scorecard when proof carriers shift confidence.
- Other sibling operator runbooks (`ADDING_A_NEW_CAPABILITY.md`,
  `INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`,
  `CROSS_PLATFORM_INCIDENT_TRIAGE.md`,
  `COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md`,
  `LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`,
  `PRIVACY_BUDGET_AND_POSTERIOR_AGGREGATION_TRIAGE.md`,
  `FLEET_CONVERGENCE_DIAGNOSTICS_AND_DEESCALATION.md`).
