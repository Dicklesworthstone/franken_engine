# FE-CLAIM-016..021 Matrix-Promotion Decision (G.10)

Operator record for the **Track-G theorem-backed-compiler** matrix-promotion
umbrella — the single fail-closed checkpoint that decides whether the six
claims `FE-CLAIM-016`..`FE-CLAIM-021` may sit at `observed` in the
claim-to-proof matrix. They promote **simultaneously** or not at all.

## Bead anchors

- This decision: **bd-cixqu.7.13** (G.10 — matrix promotion umbrella,
  `HYPOTHESIS -> OBSERVED` for the six theorem-backed-compiler claims).
- Edit child: **bd-cixqu.7.16** (G.13 — the actual matrix JSON + README edits,
  gated on this decision flipping to `PROMOTE_ALL_TO_OBSERVED`).
- Upstream gate: **bd-cixqu.7.12** (G.9 — `run_rgc_theorem_backed_compiler.sh`,
  the proof-recheck mechanism that consumes the G.2..G.8 proof artifacts).
- Track parent: **bd-cixqu.7** (Track G).
- Downstream: **bd-cixqu.47** (GA-EXIT) depends on this decision being honest.

The six claims and the Track-G work each rests on:

| claim | scope | tracks | claim text |
|---|---|---|---|
| FE-CLAIM-016 | security | G.2, G.3 | IFC lattice + capability-algebra formal spec with isomorphism to the Rust impl |
| FE-CLAIM-017 | compiler | G.6 | proof-carrying compilation: each lowering preserves source semantics |
| FE-CLAIM-018 | policy | G.6, G.7 | policy evaluation with formal semantics + proven merge operators |
| FE-CLAIM-019 | optimization | G.8 | mathematically-equivalent fast paths behind isomorphism proofs |
| FE-CLAIM-020 | policy | G.7, G.8 | theorem-backed compiler for high-assurance policy governance |
| FE-CLAIM-021 | policy | G.7 | Policy Theorem Engine: SMT-backed monotonicity / non-interference / attenuation |

## The promotion rule

The six matrix entries may only read `observed` when **all six** carry a real,
re-runnable, machine-checked theorem proof. Concretely, for each claim the G.9
proof bundle (`artifacts/rgc_theorem_backed_compiler_inputs/<claim>.proof.json`,
schema `franken-engine.theorem-backed-compiler.proof.v1`) must recheck clean:

1. present and parseable; and
2. `verdict == "proven"`; and
3. `content_hash` matches the canonical proof body (tamper-evident); and
4. `generated_utc` is fresh (≤ 30 days); and
5. the proof is **not a fixture / simulated artifact** — its `source_module` is
   not a fixture marker and its body carries no simulation fragment
   (`simulate`, `placeholder`, `MockCertificate`, `hot_paths_simulation`,
   `selftest-fixture`).

If any condition fails for any claim, the honest outcome is that all six stay
`hypothesis`. Promoting on a fixture or a simulated verdict is the exact
over-claim `bd-reality-005` exists to prevent.

## Current decision: STAY_HYPOTHESIS

As of the 2026-08-14 reality check, **none of the six claims carries a qualifying
current theorem proof.** The live gate finds zero of six proof files in
`artifacts/rgc_theorem_backed_compiler_inputs/`. Source-level producers and
verification machinery have advanced since the original G.10 decision, but
machinery is not a re-runnable artifact and cannot promote a claim by itself:

- **FE-CLAIM-016 (G.2/G.3) — unsound target-closure boundary.** The default
  `lake build` checks the IFC, SME, and claim-evidence targets declared in
  `proofs/lean4/lakefile.lean`; it does not include the capability-algebra
  files. Direct checks of `CapabilityAlgebraSpecification.lean` and
  `CapabilityAlgebraIsomorphism.lean` fail. The Lean proof producer nonetheless
  enumerates theorem declarations from every `*.lean` source after the narrower
  default build, so an emitted bundle would overstate which targets were
  successfully checked. The producer must bind theorem enumeration to the exact
  successful target set, every claim-relevant target must check, and the result
  must survive the independent bundle rechecker.

- **FE-CLAIM-017 (G.6) — validators and an emitter helper, no live producer.** The
  translation validators (`exception_translation_validator.rs`,
  `iterator_protocol*`, `hostcall_capability*`, `async_translation_validation.rs`,
  `generator_translation_validator.rs`, `ifc_label_translation_validator.rs`,
  `full_ir_translation_validator.rs`) run real differential abstract
  interpreters that reject covered semantics-breaking transforms, and
  `translation_validation_proof_carrier.rs` can serialize a bundle from a
  supplied result. No product/operator producer currently drives that helper
  over a real non-empty compiler transformation and emits a qualifying witness.

- **FE-CLAIM-018 / 021 (G.7) — real Z3 path, no qualifying live bundle.**
  `policy_theorem_engine.rs::verify_single_theorem` now defaults to
  `SmtSolver::Z3`, invokes Z3 with the standard negate-and-check pattern, and
  fails closed on `sat`, `unknown`, timeouts, and subprocess errors. The
  `emit_track_g_proof_bundles` binary drives a representative theorem corpus
  and can emit FE-CLAIM-018/021 bundles. No such current bundle is present for
  the live gate to recheck, so neither broad claim is yet observed.

- **FE-CLAIM-019 (G.8) — fail-closed verification paths, no qualifying live
  bundle.** `optimization_proof_carriers.rs::verify_proof_obligation` routes
  formal/theorem obligations through Z3, finite-model/symbolic obligations
  through bounded Z3 scripts, and property/differential obligations through
  bounded deterministic sample runners. Empty formulas, missing samples,
  unsupported syntax, and generated prose fail closed. No current non-fixture
  full-optimization proof bundle is present.

- **FE-CLAIM-020 (G.7/G.8) — no end-to-end composition proof.** The broad
  theorem-backed-compiler claim depends on qualifying 018/019/021 evidence.
  There is no current bundle composing those lanes into a re-runnable,
  non-fixture end-to-end compiler proof.

Therefore the six claims correctly remain at `hypothesis`, and the gate exits
`0` because the matrix state is consistent with the (absent) live proof
evidence. The gate enforces the mechanical floor; this document records the
honesty bar.

## Running the gate

```bash
# Evaluate the live tree and emit a decision artifact.
./scripts/run_fe_claim_016_021_promotion_gate.sh ci

# Prove every decision path (real / none / fudge / fixture / tamper /
# not-proven / under-claim) without needing the Rust crate to link.
./scripts/run_fe_claim_016_021_promotion_gate.sh selftest

# Validate a previously emitted decision artifact.
./scripts/run_fe_claim_016_021_promotion_gate.sh verify <artifact.json>

# Full smoke (check + selftest + live consistency).
./scripts/e2e/fe_claim_016_021_promotion_gate_smoke.sh run
```

### Inputs (environment overrides)

| Variable | Default | Meaning |
|---|---|---|
| `CLAIM_TO_PROOF_MATRIX_PATH` | `docs/claim_to_proof_matrix_v1.json` | Matrix to read the six claim states from. |
| `FE_CLAIM_016_021_PROOF_BUNDLE_DIR` | `artifacts/rgc_theorem_backed_compiler_inputs` | G.9 proof bundle to recheck (also honours `RGC_THEOREM_BACKED_COMPILER_BUNDLE_DIR`). |
| `FE_CLAIM_016_021_PROMOTION_ARTIFACT_ROOT` | `artifacts/fe_claim_016_021_promotion` | Decision-artifact output root. |

## Fail-closed behaviour

The gate is bidirectional but conservative:

- **Over-claim → hard fail (exit 1).** If any matrix entry reads `observed`
  while its proof is missing, stale, tampered, unproven, or a fixture, the gate
  emits a stable code — `FeClaim016_021PromotionError::ObservedWithoutProvenTheorem`
  or `…::ObservedWithFixtureProof` — and fails. This is the anti-fudging guard
  the GA-exit bundle (bd-cixqu.47) depends on.
- **Under-claim → advisory (exit 0).** If real proofs exist but the matrix still
  reads `hypothesis`, the gate passes with an advisory recommending promotion.
  Claiming less than the evidence supports is never a gate failure.
- **Umbrella semantics.** The aggregate decision is `PROMOTE_ALL_TO_OBSERVED`
  only when all six claims carry a real proven proof; otherwise
  `STAY_HYPOTHESIS`.

## When the proofs finally land

To promote FE-CLAIM-016..021 to `observed`:

1. Complete the remaining producer and target-closure work and emit a real
   `<claim>.proof.json` per claim into
   `artifacts/rgc_theorem_backed_compiler_inputs/` with `verdict: "proven"`, a
   correct `content_hash`, a fresh `generated_utc`, and a non-fixture
   `source_module`:
   - 016: make every claim-relevant Lean target explicit, make them all pass,
     and bind the emitted theorem inventory to exactly those checked targets;
   - 017: drive the existing helper from a product/operator producer over a
     real non-empty compiler transformation;
   - 018/021: execute the Z3-backed producer and independently recheck the
     emitted theorem bundles against the exact source revision;
   - 019: emit and independently recheck a non-fixture bundle from the bounded
     Z3 and differential/property runner paths over product obligations;
   - 020: compose the above end-to-end.
2. Re-run `./scripts/run_rgc_theorem_backed_compiler.sh ci` and confirm all six
   proofs recheck clean.
3. Re-run `./scripts/run_fe_claim_016_021_promotion_gate.sh ci` and confirm the
   decision flips to `PROMOTE_ALL_TO_OBSERVED`.
4. (G.13 / bd-cixqu.7.16) Edit each matrix entry to `observed`, point its
   `artifact_path` at the proof bundle (with a `repro.lock`), set a numeric
   `freshness_days <= 30`, set `verification_command` to
   `./scripts/run_rgc_theorem_backed_compiler.sh ci`, remove the
   `downgrade_text`, and update the README "Where Each Capability Stands Today"
   section. Re-run this gate **and**
   `./scripts/run_claim_to_proof_matrix_gate.sh ci` until both are green.
