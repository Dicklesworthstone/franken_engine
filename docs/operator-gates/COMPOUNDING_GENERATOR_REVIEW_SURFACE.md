# Compounding Generator Operator Review Surface

Operator runbook for the FrankenEngine compounding red-team generator
(Track U). Covers how to inspect a generation-campaign result set, how
to manually promote or reject each generated attack, and how to read
the attack-class taxonomy that the generator emits alongside its
candidates.

## What the compounding generator is (and isn't)

The compounding generator is an *attack-invention* lane. It composes
small mutation primitives (capability-shadowing, ambient-authority
laundering, computed-member evasion, etc. — the same primitives the
red-team scenario corpus already names) into novel multi-step attack
sequences, runs them against FrankenEngine, and reports candidates
the runtime did not refuse.

It is **not** an adversarial fuzzer. A fuzzer randomises inputs; the
compounding generator randomises *compositions of attack primitives*
and keeps only the candidates that compose into a behaviour the
existing red-team corpus does not already cover (the novelty
detector in `bd-cixqu.21.3`).

Each campaign run produces a candidate set; operator review decides
which candidates promote into the curated red-team corpus, which are
rejected as duplicates of existing coverage, and which need engine
fixes before the runtime can claim coverage.

## Bead anchors

- Track parent: **bd-cixqu.21** (Track U — compounding red-team
  generator, autonomous attack invention).
- This document: **bd-cixqu.21.6** (U.6 operator-runbook).
- Engine surface:
  - `crates/franken-engine/src/counterexample_synthesizer.rs` —
    counterexample synthesis primitives.
  - `crates/franken-engine/src/adversarial_campaign.rs` — campaign
    orchestration + candidate aggregation.
  - `crates/franken-engine/src/red_team_compromise_rate_metric_gate.rs` —
    the metric gate that consumes the curated red-team corpus once
    candidates promote.
- Sibling baseline corpus:
  `crates/franken-engine/tests/red_team_scenarios/` (16 entries today;
  the destination promotion target for accepted candidates).
- Sibling runbooks:
  [`LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`](./LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md)
  (same 4-category triage pattern; this runbook mirrors that shape).

## Campaign result set — what to inspect

Each campaign run emits a result-set bundle under
`artifacts/compounding_generator/<campaign_id>/`:

| File | What it carries |
|---|---|
| `campaign_manifest.json` | Campaign id, generation parameters (mutation depth, primitive set, target capability surface), seed values, run window. |
| `candidates.jsonl` | One row per generated candidate. Includes `candidate_id`, attack-class taxonomy classification, the composed primitive chain, the workload that exhibited the divergence, FrankenEngine's response (refused / accepted), and a novelty score. |
| `novelty_report.json` | Per-candidate novelty signal: distance from the curated corpus, name of the nearest existing scenario if any, and the `bd-cixqu.21.3` novelty-detector verdict (`Novel` / `NearDuplicate` / `Duplicate`). |
| `engine_response.jsonl` | What FrankenEngine actually did for each candidate (the `LaneAction` it produced, the `LoweringPipelineError` it emitted if any, the evidence atoms it signed). |
| `run_manifest.json` | Bundle identity, replay command, content hashes per the standard proof-artifact contract. |
| `events.jsonl` | Per-step event stream for the campaign. |

Read the files in this order:

1. `campaign_manifest.json` — confirm the generation parameters match
   what you expected. A campaign that ran with the wrong primitive
   set produces unreviewable candidates.
2. `novelty_report.json` — filter the candidates first. `Duplicate`
   candidates are immediate rejects; only `Novel` and `NearDuplicate`
   need per-candidate review.
3. `candidates.jsonl` + `engine_response.jsonl` paired — for each
   `Novel` candidate, read the candidate row alongside the engine's
   actual response. The decision branches off the response shape
   (refused vs accepted), not off the candidate alone.

## Attack-class taxonomy

The generator emits each candidate with one of the following
`AttackClass` values. The taxonomy mirrors the curated corpus's
`attack_vector` field so a promoted candidate slots directly into the
existing red-team category set.

| `AttackClass` | What the candidate does | Curated-corpus exemplar |
|---|---|---|
| `CapabilityShadowing` | Reaches an ambient surface through a transitive re-export chain whose root is never named at the call site. | `capability_shadowed_import` (bd-cixqu.3.6). |
| `EffectLaundering` | Passes an effect-carrying value to a less-privileged callee that promises not to use it but does. | `typed_effect_laundering_downcast`. |
| `AmbientReach` | Reaches ambient authority via `globalThis`, `Reflect.apply`, or a Proxy trap. | `ambient_authority_via_globalthis`, `reflect_apply_authority_smuggling`, `proxy_trap_authority_smuggling`. |
| `RuntimeCompile` | Uses `eval` or `new Function(body)` to defeat static capability accounting. | `eval_capability_evasion`, `function_constructor_evasion`. |
| `MemberAccessEvasion` | Uses computed-member or dynamic-import indirection to bypass a name-resolution scan. | `computed_member_capability_evasion`, `dynamic_import_capability_evasion`. |
| `ScopeChainSmuggling` | Opens a `with`-block over an ambient binding to make ambient names free identifiers. | `with_block_scope_smuggling`. |
| `DeclassificationBypass` | Cross-clearance flow without a signed declassification receipt. | `declassification_without_receipt`. |
| `Compound` | A composition of two or more of the above. The novel core of the generator's output. | (No single-primitive exemplar — by design.) |

`Compound` is the class operators spend the most review time on. It
is also where the generator earns its keep: any single-primitive
attack the curated corpus already covers; the value-add is the
multi-step combinations.

## Per-candidate review decision tree

For each `Novel` (or `NearDuplicate`) candidate:

### 1. Did FrankenEngine refuse the candidate?

Read `engine_response.jsonl` for the matching `candidate_id`.

**Yes — refused** (engine produced a `LoweringPipelineError::UnauthorizedFlow`
or `UnsupportedSyntax`, or routed the workload through a fail-closed
path). Continue to step 2.

**No — accepted** (engine ran the workload to completion without
refusing). This is the high-value case: the generator found an attack
the runtime did not catch. Continue to step 3.

### 2. Refused candidate — promote, reject, or document?

A refused candidate proves FrankenEngine already catches the attack
class. The review question is whether the candidate is worth promoting
into the curated corpus as a regression test:

- **Promote** when the novelty score is high AND the attack-class is
  one the curated corpus does not yet exemplify (e.g. a novel
  `Compound` whose primitive chain has no analogue in the 16 existing
  scenarios). Promotion = add the candidate as a new entry under
  `crates/franken-engine/tests/red_team_scenarios/` and update
  `EXPECTED_SCENARIOS` in
  `tests/red_team_scenario_manifest_validation.rs`.
- **Reject as duplicate** when the novelty detector flagged
  `NearDuplicate` and operator inspection confirms the candidate
  exercises the same primitive chain as an existing scenario.
  Rejection is recorded but does not change the curated corpus.
- **Document and reject** when the candidate is novel but the
  attack-class is uninteresting for the deployment lane (e.g. the
  lane does not grant the capability the attack targets). Record the
  decision in the campaign's review log; do not promote.

### 3. Accepted candidate — engine bug or coverage gap?

An accepted candidate means the runtime did NOT refuse the attack.
This is the case that drives engine fixes. The review question is
which class of fix:

- **Engine bug** — the runtime should have refused. The capability
  contract names the surface the candidate reached, and the surface
  is not declared by the workload's manifest. File an engine bead
  with priority P1; cite the `candidate_id` + the engine response.
  Acceptance for the bead: the candidate joins the regression corpus
  AND the runtime now refuses it.
- **Coverage gap** — the runtime is operating as designed, but the
  capability contract has no rule covering the attack class. The
  candidate has discovered missing coverage rather than a bug. File a
  P2 contract-extension bead with the candidate as the motivating
  example.
- **False novelty** — the engine accepted the candidate because the
  candidate's "novelty" is actually a transformation of an accepted
  pattern (e.g. a renamed-but-equivalent benign access). Tighten the
  novelty detector by recording the candidate as a near-duplicate of
  the matching benign pattern. The bead's title prefix should be
  `bd-cixqu.21.3-tuning`.

## Manual promote / reject mechanics

The actual mechanics of promotion are mechanical:

### Promote

1. Convert the candidate's primitive chain into a `.js` fixture
   under `crates/franken-engine/tests/red_team_scenarios/<slug>.js`.
   Use the existing scenarios as the template — header comment, IIFE
   shape, `process.stdout.write(JSON.stringify(...))` envelope.
2. Author the matching `.manifest.json` declaring `attack_vector` (a
   new unique string in the corpus), `payload`, `expected_outcome`
   (node/bun `succeeds`, frankenengine `fail_closed` with a precise
   `denial_reason` if the engine refuses, OR `fail_closed: false`
   tracked under an engine-fix bead if it does not).
3. Add the slug to `EXPECTED_SCENARIOS` in
   `tests/red_team_scenario_manifest_validation.rs` (alphabetical
   insertion).
4. Run the validation test:
   `rch exec 'env CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine
   --test red_team_scenario_manifest_validation'`. The test must
   pass; the manifest's `attack_vector` uniqueness is the canonical
   anti-duplication check.
5. Commit with the `bd-cixqu.21.6 promote` reference.

### Reject

A rejection is recorded — no code change — by appending an entry to
`artifacts/compounding_generator/<campaign_id>/review_log.jsonl`:

```jsonl
{"candidate_id": "<id>", "decision": "reject", "reason": "<duplicate|uninteresting|false_novelty>", "operator": "<agent_name>", "decided_at_utc": "<iso8601>"}
```

The review log feeds the novelty-detector retraining loop
(bd-cixqu.21.3): each rejected candidate's primitive chain becomes a
near-duplicate signal for the next campaign.

## Cross-cutting rules

- **Review every `Novel` candidate.** A campaign that emits 200
  `Novel` candidates is not a quality measure; it is workload. The
  reviewer's job is to apply the decision tree to every one. If the
  reviewer cannot keep up, the generator's mutation depth needs to
  be narrowed (a parameter in `campaign_manifest.json`).
- **Refusals are evidence too.** A candidate the engine refused
  proves the runtime works for that attack class. Promoting refused-
  by-engine candidates into the corpus is how we get regression
  tests; "the engine refused so we don't need a test" is the wrong
  intuition.
- **Do NOT promote an accepted candidate without filing the engine
  bead first.** Promoting before the fix lands creates a failing test
  in the regression corpus and stalls CI. Sequence: engine bead →
  fix lands → candidate promoted as the regression test.
- **The novelty detector is part of the trusted base.** A bug in
  bd-cixqu.21.3 produces either spurious-novel candidates (review
  workload explodes) or spurious-duplicate candidates (real novelty
  silently rejected). Tune it via the rejection log, not by editing
  the detector directly.

## What NOT to do

- **Do not** silently drop a `Novel` candidate without a review-log
  entry. The audit trail of "what the operator looked at and chose"
  is the audit trail of the curated corpus's completeness.
- **Do not** promote a `Compound` candidate without also recording
  the decomposition into its primitive chain. The curated corpus's
  value comes from per-primitive coverage; an opaque-compound entry
  does not contribute to that.
- **Do not** treat `engine accepted` as a signal that the candidate
  is "not a real attack." The engine's acceptance is precisely the
  finding the generator exists to produce.
- **Do not** retrain the novelty detector on an unreviewed candidate
  batch. The detector's training signal is the operator's per-
  candidate decision; running the loop on unreviewed candidates pins
  whatever bias the generator already has.

## Deferred (out of scope for this runbook)

The bead's full operator surface also names interactive review
tooling (a TUI panel for per-candidate triage, a promote/reject
wrapper script). These are deferred because they depend on the
candidate JSON contract being stable; landing this runbook
documents the contract so the follow-ups can target a fixed shape.

## Cross-references

- `crates/franken-engine/src/counterexample_synthesizer.rs` —
  synthesis primitives.
- `crates/franken-engine/src/adversarial_campaign.rs` — campaign
  orchestration + candidate aggregation.
- `crates/franken-engine/src/red_team_compromise_rate_metric_gate.rs` —
  the metric gate that consumes the promoted corpus.
- `crates/franken-engine/tests/red_team_scenarios/` — promotion
  target (16 entries today, bd-cixqu.3.3 + 3.6 contributed 11 of them).
- [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md) —
  broader gate catalogue.
- Sibling operator runbooks (`ADDING_A_NEW_CAPABILITY.md`,
  `INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`,
  `FORMAL_METHODS_WORKFLOW.md`,
  `CROSS_PLATFORM_INCIDENT_TRIAGE.md`,
  `COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md`,
  `LOCKSTEP_ORACLE_DIVERGENCE_TRIAGE.md`,
  `PRIVACY_BUDGET_AND_POSTERIOR_AGGREGATION_TRIAGE.md`).
