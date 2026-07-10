# Runbook: Proof-Producing Claim Spine v1 (proof.json producers → claim gate)

> Operator runbook per DW.DOCS (`bd-fqlfw.12`). Capability beads: `bd-fqlfw.6`
> (epic), `bd-fqlfw.6.1` (strict producer contract), `bd-fqlfw.6.2` (Lean
> producer), `bd-fqlfw.6.3` (translation-validator witnesses), `bd-fqlfw.6.4`
> (Z3 policy-theorem wiring), `bd-fqlfw.6.5` (claim-gate integration),
> `bd-fqlfw.6.6` (capstone gate).
> Claim state: see *Claim-state note* below — the spine makes FE-CLAIM-016/017
> promotion a mechanical consequence of live artifacts; FE-CLAIM-018..021 stay
> HYPOTHESIS **by design** in v1.

## What this does (one paragraph)

The proof spine turns "is this claim proven?" from prose into artifact state.
Proof *producers* (the Lean checker over `proofs/lean4/`, the differential
translation validators, the Z3 policy-theorem engine) emit a strict
`proof.json` (`proof_schema::ProofProducerArtifact`): claim IDs, theorem or
validator ID, input/output artifact hashes, the exact command, pinned tool
identity, a checker verdict, counterexample bindings, and a content-hash
commitment. The claim gate (`proof_spine_claim_gate.rs`) classifies each
artifact into **Proven / Counterexample / Unknown / Unavailable /
FixtureOnly** (plus **Invalid** for tampered or malformed artifacts — checked
*before* the verdict is honoured) and derives a per-claim decision:
promote-to-OBSERVED, stay-HYPOTHESIS, or demote. Promotion requires at least
one integrity-checked `Passed` artifact from the claim's *registered* producer
tool; nothing else promotes anything.

## The five claim states (and what an operator does about each)

| State | Meaning | Gate decision | Operator action |
|---|---|---|---|
| **Proven** | Integrity-checked `Passed` verdict from the registered producer. | May promote to OBSERVED. | None — cite the artifact. |
| **Counterexample** | The checker found a real divergence / proof failure. | Blocks promotion; **demotes** a currently-OBSERVED claim. | Triage the counterexample artifact; the claim wording must be downgraded until fixed. |
| **Unknown** (`Inconclusive`) | The checker ran but reached no verdict (e.g. solver timeout). | Blocks promotion (treated like Unavailable, preserving repro.lock discipline). | Re-run with a longer timeout or a pinned toolchain; never hand-promote. |
| **Unavailable** | The backend could not run (toolchain missing, build broke). | Blocks promotion. | Fix the environment (see *Refreshing a producer artifact*), re-run the producer. |
| **FixtureOnly** | The backend is a fixture and may never promote a real claim. | **Rejected** as backing evidence (mirrors the `MockCertificate` treatment); a regression to fixture demotes. | Wire the real backend; a fixture can never be an answer. |

Two additional failure modes surface in gate findings: **Invalid** (content-hash
mismatch / malformed body — demotes, because a tampered `Passed` is worse than
no artifact) and **UnregisteredProducer** (a tool not registered for the claim
emitted an artifact for it — can never promote, whatever its verdict).

## Registered producers (v1)

| Claim | Registered producer tool | Producer surface |
|---|---|---|
| `FE-CLAIM-016` (machine-checked Lean proofs) | `lean4` | `franken_lean_proof_producer` binary over `proofs/lean4/` |
| `FE-CLAIM-017` (translation validation) | `translation-validator` | witness bridge `TranslationValidationWitnessArtifact::to_proof_producer_artifact` |
| `FE-CLAIM-018`..`FE-CLAIM-021` | **none (v2-deferred)** | stays HYPOTHESIS via `Unavailable` — see *Claim-state note* |

## Normal use

```bash
# Full capstone gate -> content-addressed bundle under artifacts/dw_proof_spine/<ts>/
./scripts/run_dw_proof_spine.sh ci                 # routes Cargo through rch
DW_RUN_LOCAL=1 ./scripts/run_dw_proof_spine.sh ci  # local fallback when rch is down
# (optional) DW_CARGO_TARGET_DIR=<dir> isolates the local Cargo target dir.

# Verify / replay an emitted bundle:
./scripts/e2e/dw_proof_spine_replay.sh bundle artifacts/dw_proof_spine/<ts>
./scripts/e2e/dw_proof_spine_replay.sh rerun
```

## Refreshing a producer artifact

- **Lean (FE-CLAIM-016):**
  ```bash
  # toolchain (one-time): scripts/install_lean_toolchain.sh, then warm the cache:
  (cd proofs/lean4 && lake build)
  cargo build -p frankenengine-engine --bin franken_lean_proof_producer
  ./target/debug/franken_lean_proof_producer \
    --proof-dir proofs/lean4 --out FE-CLAIM-016.proof.json \
    --invocation-id refresh-$(git rev-parse --short HEAD) --ticks 0 --epoch 1
  ```
  Exit `0` = `Passed`; exit `4` = a non-promotable artifact was still written
  for triage (inspect `checker_result.Unavailable.reason`); exit `2` = usage/IO.
- **Translation-validator witnesses (FE-CLAIM-017):** witnesses are emitted by
  `emit_translation_validation_witness_artifact` /
  `emit_fe_claim_017_proof_bundle` from real validation runs; the pilot lane is
  `scripts/run_rgc_translation_validation_pilot.sh`. Bridge any witness into
  the strict contract with `to_proof_producer_artifact()`.
- **Z3 policy theorems:** `policy_theorem_engine.rs` routes supported
  obligations through Z3 (`verify_with_z3`) and emits proof bundles for
  *Proven* results only; Unknown/timeout never promotes (bd-fqlfw.6.4).

## Reading the artifact bundle (`artifacts/dw_proof_spine/<timestamp>/`)

| File | Answers |
|---|---|
| `run_manifest.json` | Did it pass? source revision, host facts, content hashes, verify command. |
| `events.jsonl` | Step log: every cargo lane + the live producer leg, with timing and output hashes. |
| `commands.txt` | Exact commands run, in order. |
| `proof_spine_e2e/FE-CLAIM-016.proof.json` | The live Lean producer artifact (present only when lake/lean + the mathlib cache were available). |

## Exit codes / triage

| Symptom | Likely cause | Fix |
|---|---|---|
| Gate step `franken_lean_proof_producer … (pass a)` fails | Lean corpus no longer builds | `(cd proofs/lean4 && lake build)` and read the compile error; the artifact written to the bundle carries the reason. |
| `live_e2e` recorded as `skip` | lake/lean not on PATH or mathlib cache absent | `scripts/install_lean_toolchain.sh`, then one warm `lake build` in `proofs/lean4/`. A skip is an explicit evidence state — the cargo lanes still prove the library path. |
| `proof.json byte-identity across passes` fails | Nondeterminism leaked into the producer (unpinned invocation id / wall-clock) | The gate pins `--invocation-id/--ticks/--epoch`; diff the two passes in the bundle to find the drifting field. |
| Replay says `CONTENT-HASH MISMATCH` | Bundle edited after emission | Not a certifying bundle; re-run the gate. |
| Replay says `claim_ids drifted` | The preserved proof.json binds claims other than FE-CLAIM-016 | Tamper signal — a fabricated v2-deferred claim id fails closed. |
| A claim you expected OBSERVED reads `ProducerDidNotRun` | No live artifact references the claim | Run the producer for that claim (see *Refreshing a producer artifact*). |

## Claim-state note (binding)

`FE-CLAIM-016` and `FE-CLAIM-017` may promote **only** through live artifacts
under this spine. `FE-CLAIM-018`..`FE-CLAIM-021` (rich SMT encodings of every
policy theorem, a real optimization-equivalence model checker) are
**v2-deferred** (`bd-cixqu.7.17`): the gate returns `Unavailable` for them and
refuses even a syntactically-valid `Passed` artifact. This is not a failure —
it is a deliberate, honest boundary; the promotion decision record is
`docs/operator-gates/FE_CLAIM_016_021_PROMOTION_DECISION.md`. Flipping the
claim-to-proof matrix rows themselves remains governed by
`./scripts/run_claim_to_proof_matrix_gate.sh ci` and the promotion beads —
this spine supplies the artifact-state *inputs* to that decision, not a bypass
around it.
