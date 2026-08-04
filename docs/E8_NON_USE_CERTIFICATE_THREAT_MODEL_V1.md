# E8 Non-Use Certificate — Threat Model Boundary (v1)

> Owning bead: `bd-fqlfw.8.4` (E8.T4 — fail-closed soundness + IFC-hole
> closure + explicit threat model). Companion contracts:
> `docs/e8_analyzed_subset_refusal_ledger_v1.json` (refusal vocabulary,
> bd-fqlfw.8.4.1.1) and `docs/e8_refusal_ledger_schema_v1.json` (receipt
> schema, bd-fqlfw.8.4.1.2).

This document pins what an E8 non-use certificate does and does not claim.
It is the wording boundary the certifier (`non_use_certificate.rs`), the
refusal ledger (`data_contract.rs`), and the analyzed-subset scan
(`e8_analyzed_subset.rs`) enforce mechanically. Nothing here is aspirational:
every statement is backed by a fail-closed code path and a test.

## Scope statement

**The certificate covers EXPLICIT DATA FLOWS ONLY** (`explicit_flow_ifc_v1`):
label propagation through value derivation, property access, calls and
returns, exception values, and capability-gated host-boundary crossings.

**Out of scope — the certificate never asserts anything about:**

| Channel | Why it is out of scope |
|---|---|
| Covert channels (resource usage, cache state, allocation patterns) | Not observable in the explicit-flow label algebra. Refusal code: `out_of_scope_covert_channel`. |
| Timing channels (wall-clock-dependent signalling) | The runtime is deterministic-first, but timing observability sits below the label algebra. Refusal code: `out_of_scope_timing_channel`. |
| Control-flow implicit channels (`if (secret) { publicSink(1) }`) | Explicit-flow IFC joins labels on *data* derivation, not on branch decisions. A branch on Secret data does not taint values assigned inside the branch arms. |
| CPU side channels (Spectre/Meltdown class) | Hardware-side; see the repository-wide threat model in `README.md`. |

Out-of-scope guarantees are unexpressible by construction: the
`RequestedOutputClaim` vocabulary is a closed enum (`no_flow`,
`output_independent_of`, `capability_not_used`) with no covert- or
timing-channel claim type, so a contract cannot smuggle such a request past
the certifier. The `out_of_scope_covert_channel` / `out_of_scope_timing_channel`
refusal codes exist in the pinned vocabulary (and in the XIX-D adversarial
fixtures) so that any future surface that *does* accept free-form guarantee
requests must refuse them explicitly rather than silently narrowing them.

## The analyzed subset (bd-fqlfw.8.4)

Certification is bounded by the **analyzed explicit-flow subset**: the set of
IR op kinds whose baseline-interpreter label propagation is production-wired
and regression-tested at HEAD. The classification lives in
`e8_analyzed_subset::classify_op` as an exhaustive match with **no wildcard
arm** — adding a new IR op variant refuses to compile until it is consciously
classified, so new constructs can never silently join the certifiable subset.

Analyzed (v1): literals, binding load/store, binary/unary/assign operators,
property get/set/delete/accessor definition (bd-0zybl), calls, method calls,
construction and returns including callback lanes (bd-ooaka.1), array/object
construction and spread, template literals, throw/try/catch/finally exception
values (bd-l0d6z), `this`/`new.target`/`super` loads, pure control-flow and
stack ops, function declaration/creation (bodies are scanned recursively),
and capability-gated hostcall edges.

Unproven — fail closed with `unproven_ifc_propagation` (v1): `await`,
`yield`, async and generator function creation (resumption-frame label
preservation is uncertified even when the body contains no suspend op),
`for..in` / `for..of` / iterator-close lanes, and module-graph edges
(`import` / `export` pull code the scan did not analyze). Ambient-authority
accessors (`process`, `require`, `eval`, `fetch`, …) are likewise unproven
flow surfaces: they reach host state outside the typed capability membrane.

Widening the analyzed subset is a reviewed decision: it requires citing the
interpreter label-propagation regression tests that prove the lane, updating
`classify_op`, and updating this document. The unproven set is pinned by
`e8_analyzed_subset::tests::classify_op_pins_the_unproven_set`.

## Soundness argument (why the certificate cannot silently overclaim)

1. **Scan-or-refuse.** A data-contract run's refusal ledger is derived from
   the analyzed-subset scan of the exact run-input bytes (hash-bound;
   mismatch is `run_input_hash_mismatch`, class `fail_closed`). No scan ⇒
   `missing_flow_proof_obligation` ⇒ uncertified.
2. **Unanalyzed ⇒ uncertified at span X.** Every construct outside the
   analyzed subset produces a refusal code with source-span provenance
   (`<file>:<line>:<col>`) where the lowering stamped one; spanless surfaces
   additionally record `missing_source_span` (class `degraded`). Any refusal
   code blocks certification (`must_block_certificate = true`).
3. **Status is derived, never asserted.** The certificate reaches
   `certified_within_analyzed_scope` only when the refusal ledger is an
   empty, scan-backed `certifiable_subset` receipt AND every requested claim
   evaluates `holds_within_analyzed_scope`. Any weaker verdict on any claim
   downgrades the whole certificate to `uncertified` while keeping per-claim
   verdicts visible.
4. **The receipt is never a certificate.** The ledger schema pins
   `positive_non_use_claim_allowed = false` unconditionally: only the signed
   certificate may state non-use, and only within the analyzed scope.
5. **Positive claims over-approximate.** The use certificate records what the
   run *may* have bound, held, or reached; over-approximation in that
   direction never launders a hidden use into a non-use claim.

## Historical IFC holes (closed, regression-tested)

| Hole | Status at HEAD |
|---|---|
| bd-0zybl — `GetProperty` under-tainting | Fixed; production join sites + regression tests in `baseline_interpreter.rs` (`get_property_joins_object_label_onto_dst`). |
| bd-ooaka.1 — callback lanes propagated no labels | Fixed; receiver/argument labels join onto call results, regression-tested. |
| bd-l0d6z — thrown values lost labels | Fixed; exception values carry labels through catch/finally. |

The analyzed subset *assumes only* lanes with landed fixes and tests; every
lane historically implicated in under-tainting that lacks such evidence
(iterator protocol, async resumption) remains in the unproven set.

## Acceptance criteria (tested)

- A run containing an unanalyzed construct yields `uncertified` with an
  `unproven_ifc_propagation` refusal carrying span provenance — never a
  false non-use claim (`non_use_certificate_integration.rs`,
  `data_contract_integration.rs`).
- An adversarial unanalyzed Secret-to-sink scenario never produces
  `holds_within_analyzed_scope` on a `NoFlow` claim while the ledger blocks
  certification.
- A fully-analyzed run with complete evidence certifies within the analyzed
  scope, and the certificate wording states the scope and this boundary
  document.
