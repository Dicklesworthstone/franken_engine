# Lockstep Oracle Divergence Triage

Operator runbook for cross-runtime lockstep-oracle divergence reports.
The Track I pipeline (`bd-cixqu.9.1`..`9.3`) runs FrankenEngine,
Node, and Bun against the same workload and classifies every
divergence into one of four categories. Each category has a different
triage path; the wrong choice locks in either an unfixed bug or an
unjustified compatibility-debt overhead.

## Bead anchors

- Track parent: **bd-cixqu.9** (Track I — cross-runtime lockstep
  oracle full Node + Bun pipeline; promote SIMULATED → OBSERVED).
- This document: **bd-cixqu.9.6** (I.6 operator-runbook).
- Engine surface: `crates/franken-engine/src/frx_lockstep_oracle.rs` +
  `crates/franken-engine/src/runtime_lockstep_helpers.rs`.
- Gate script: `scripts/run_rgc_lockstep_oracle_pipeline.sh`.
- Sibling runbooks: [`CROSS_PLATFORM_INCIDENT_TRIAGE.md`](./CROSS_PLATFORM_INCIDENT_TRIAGE.md)
  (cross-platform hash divergence — different problem, same diagnose /
  decide / act / verify pattern).

## The four divergence categories

Every divergence the oracle reports carries a `DivergenceClassification`
enum value. The triage path branches on that value first.

| Category | What it means | First action |
|---|---|---|
| `EngineBug` | FrankenEngine produced a result that violates the language spec or the documented runtime contract. Node and Bun agree with each other; FrankenEngine disagrees with both. | File an engine bead. The fix lands in FrankenEngine; the divergence is rejected. |
| `IntentionalImprovement` | FrankenEngine produced a spec-compliant or contract-compliant result that is *stricter* than Node/Bun (e.g. fails-closed where Node would silently accept). Node and Bun agree with each other; FrankenEngine differs in the safer direction. | Promote to acceptance via the signed `promote_intentional_improvement.sh` flow. Record the operator's reasoning + signed acceptance into the audit ledger so the divergence stops surfacing in subsequent runs. |
| `CompatibilityDebt` | All three runtimes diverge; the spec is ambiguous or implementation-defined in this region. FrankenEngine's choice is defensible but the divergence is a real adoption friction. | Document the debt under `docs/compatibility/`. Do NOT silence the divergence — leave it surfacing so a future spec-clarification can re-classify it. |
| `EcosystemAmbiguity` | Node and Bun disagree with each other; FrankenEngine matches one of them. This is the ecosystem's own divergence, not FrankenEngine's. | File a bead only if FrankenEngine's choice is operationally costly; otherwise document the ecosystem split in the compatibility ledger and move on. |

The classification is produced upstream by the oracle's
`DivergenceClassifier`; this runbook documents how to act on it, not
how the classifier decides.

## Typed evidence atom (what the divergence record carries)

Each divergence emitted by the oracle is a typed evidence atom with
the following fields. Read them in this order when triaging:

| Field | What it tells you |
|---|---|
| `divergence_id` | Stable id (UUIDv7) — cite this in any bead you file. |
| `workload_id` | The workload that triggered the divergence. |
| `classification` | The `DivergenceClassification` value (one of the four above). The first branch in the triage decision tree. |
| `franken_result` | The exact value/exception FrankenEngine produced. |
| `node_result` | The exact value/exception Node produced. |
| `bun_result` | The exact value/exception Bun produced. |
| `spec_anchor` | Optional ECMA-262 / Test262 / WHATWG section reference the classifier matched against. Empty for `EcosystemAmbiguity`. |
| `frankenengine_position` | A short string describing FrankenEngine's documented contract for this surface. Read this BEFORE concluding "engine bug" — the position may already justify the divergence. |
| `replay_command` | The exact shell command that reproduces this divergence locally. |
| `bundle_path` | The artifact bundle that captured the oracle run. |
| `severity_score` | Numeric severity (0-1000 millionths) the classifier assigned. High severity does NOT imply category; severity is orthogonal to which of the four categories applies. |

The `franken_result` / `node_result` / `bun_result` triple is the
ground truth. Treat the `classification` as a starting hypothesis: the
classifier can be wrong, and a careful operator re-derives the
classification from the triple. The decision trees below are the
re-derivation procedure.

## Per-category triage decision trees

### `EngineBug`

**Trigger pattern**: Node and Bun produce the same result; FrankenEngine
differs.

**Decision tree**:

1. Confirm `node_result == bun_result`. If they actually differ, the
   classifier was wrong — re-route to `EcosystemAmbiguity` below.
2. Read `spec_anchor`. If empty, the classifier could not anchor the
   divergence to a spec section — escalate to a Track G maintainer
   before filing as a bug. A bug without a spec anchor is hard to
   prioritise.
3. Read `frankenengine_position`. If it says "deliberately stricter
   than spec for security/auditability reasons" (a non-empty
   intentional-deviation marker), re-route to `IntentionalImprovement`
   below — the classifier mis-categorised.
4. Otherwise, file an engine bead with:
   - `divergence_id` + `workload_id` + `bundle_path` cited.
   - Priority P1 if the spec section is normative (MUST/SHALL), P2 if
     informative (SHOULD), P3 if non-normative.
   - Acceptance: a regression test that re-runs `replay_command` and
     asserts FrankenEngine matches the Node/Bun result (and ideally
     the spec example, where one exists).
   - Labels: `track-I`, `engine-bug`, plus the spec section number as
     a tag (e.g. `ecma-262-section-7.2.15`).

### `IntentionalImprovement`

**Trigger pattern**: Node and Bun agree; FrankenEngine differs in the
safer direction (rejects what they accept, signs what they leave
unsigned, etc.).

**Decision tree**:

1. Confirm `node_result == bun_result` AND `franken_result` is
   strictly safer (rejection where they accepted, error where they
   silently coerced, etc.). If FrankenEngine's result is less safe,
   re-route to `EngineBug`.
2. Read `frankenengine_position`. It MUST be non-empty for an
   intentional improvement; an unjustified divergence is not an
   improvement, it's a bug. If empty, re-route to `EngineBug`.
3. Confirm the divergence is reproducible: re-run `replay_command`
   locally. A non-reproducible improvement claim is an artifact of
   harness noise.
4. Promote via the signed acceptance flow:
   - Author runs `runbooks/scripts/promote_intentional_improvement.sh
     <divergence_id>` (tracked under bd-cixqu.9.6 follow-up).
   - The script records: operator identity, signed reasoning,
     reference to `frankenengine_position` text, and the typed
     evidence atom hash.
   - Once recorded, subsequent oracle runs filter this `divergence_id`
     out of the surfaced report — it appears in the audit ledger but
     not in the actionable triage queue.
5. Do NOT promote without the signed acceptance. An IntentionalImprovement
   that the oracle keeps surfacing has not been accepted; the audit
   trail is what separates the two.

### `CompatibilityDebt`

**Trigger pattern**: All three runtimes diverge. The spec section the
classifier matched is marked "implementation-defined" or
"implementation-dependent".

**Decision tree**:

1. Confirm all three results differ. If two agree, the classifier was
   wrong — re-route to `EngineBug` or `IntentionalImprovement` based
   on which pair agrees.
2. Read `spec_anchor`. The spec section MUST cover an
   implementation-defined behaviour. If the section is normative, the
   classifier was wrong — re-route to `EngineBug` (multiple engines
   are simultaneously wrong, but they're still wrong).
3. Document the debt:
   - Add an entry to `docs/compatibility/COMPATIBILITY_DEBT_LEDGER.md`
     (one of the runbook's expected sibling artifacts) with:
     `workload_id`, `spec_anchor`, all three `_result` fields, and a
     one-sentence rationale for FrankenEngine's choice.
   - Cite the `divergence_id` so the ledger entry round-trips back to
     the evidence atom.
4. Do NOT file an engine bead. CompatibilityDebt is not a bug; it's a
   choice the spec leaves open. Filing it as a bug churns the queue
   for no fix.
5. Re-classify if the spec clarifies in a future revision. The ledger
   entry's spec_anchor is the hook for that revisit.

### `EcosystemAmbiguity`

**Trigger pattern**: Node and Bun disagree with each other.
FrankenEngine matches one of them (or neither).

**Decision tree**:

1. Confirm `node_result != bun_result`. If they actually agree, the
   classifier was wrong — re-route to `EngineBug` or
   `IntentionalImprovement`.
2. Decide on operational cost:
   - **High cost** (extensions in the wild rely on the choice
     FrankenEngine made and the other runtime broke them): file a
     bead to either switch FrankenEngine's choice OR document the
     ecosystem split prominently.
   - **Low cost** (no observed downstream impact): add to
     `docs/compatibility/ECOSYSTEM_DIVERGENCES.md` (sibling artifact
     to the debt ledger), cite the `divergence_id`, and move on.
3. Do NOT auto-promote either Node's or Bun's behaviour as the
   "right" answer. The Track I oracle exists precisely because Node
   and Bun do not always agree; pretending they do hides the
   ambiguity.

## Cross-cutting rules

- **Reproduce before acting.** Every category's decision tree starts
  with "confirm the result triple" and runs through `replay_command`.
  A classification you cannot reproduce is not actionable.
- **Cite the `divergence_id` everywhere.** The id is the join key
  between the oracle report, the artifact bundle, the audit ledger,
  any bead you file, and any compatibility-ledger entry. Without it,
  later operators cannot trace the decision back to the evidence.
- **Do NOT silence a divergence without a written justification.**
  Either (a) FrankenEngine should fix it (EngineBug), (b) the
  divergence is desirable and signed (IntentionalImprovement), or (c)
  the divergence is in a ledger (CompatibilityDebt /
  EcosystemAmbiguity). A divergence that disappears from the report
  with no entry in any of those four buckets is a regression in
  evidence posture.
- **Severity ≠ category.** A high-severity `CompatibilityDebt` is
  still not a bug; a low-severity `EngineBug` is still a bug. Read the
  classification first, then weigh the severity.

## When to escalate to Track I maintainers

- The classifier produced a classification you cannot re-derive from
  the result triple (a "fifth category" not in the four).
- The same `divergence_id` keeps surfacing across runs despite a
  signed promotion through `promote_intentional_improvement.sh`.
- A `replay_command` fails to reproduce a divergence the report
  showed — the oracle is non-deterministic in a way the contract does
  not permit.

## Deferred (out of scope for this runbook)

The bead's full acceptance also names:

- `runbooks/scripts/triage_lockstep_divergence.sh` — interactive /
  scripted wrapper that walks an operator through the decision tree
  given a divergence atom.
- `runbooks/scripts/promote_intentional_improvement.sh` — records the
  signed acceptance into the audit ledger.
- A frankentui panel for the cross-runtime divergence surface
  (per-workload heatmap + per-category triage queues).

These scripts and the TUI panel are deferred to a follow-up because
they depend on the oracle's typed evidence atom emitter being wired
into a stable JSON contract first; landing the operator runbook
documenting the contract lets those follow-ups target a fixed shape
rather than a moving one.

## Cross-references

- `crates/franken-engine/src/frx_lockstep_oracle.rs` — oracle entry
  point + `DivergenceClassification` enum.
- `crates/franken-engine/src/runtime_lockstep_helpers.rs` — Node/Bun
  invocation helpers.
- [`docs/operator-gates/RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md) —
  broader gate catalogue (the lockstep oracle pipeline has its own
  section there).
- [`docs/operator-gates/CROSS_PLATFORM_INCIDENT_TRIAGE.md`](./CROSS_PLATFORM_INCIDENT_TRIAGE.md) —
  sibling runbook for cross-platform `ContentHash` divergence (same
  diagnose / decide / act / verify pattern, different problem).
- Other sibling operator runbooks (`ADDING_A_NEW_CAPABILITY.md`,
  `INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`,
  `FORMAL_METHODS_WORKFLOW.md`,
  `COUNTERFACTUAL_REPLAY_OPERATOR_SURFACE.md`).
