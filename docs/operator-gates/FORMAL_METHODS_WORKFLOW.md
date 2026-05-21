# Formal-Methods Workflow Operator Guidance

Operator runbook for the FrankenEngine formal-verification surface: when
to rebuild proofs, how to triage a proof-failure, how to add a new
lemma, how to interpret SMT unsat-core output, and how to read a proof
bundle. The headline case — **"the proof failed in CI, what does that
mean and how do I unblock?"** — is treated as a first-class scenario.

## Bead anchors

- Track parent: **bd-cixqu.7** (FE-CLAIM-016..021, theorem-backed compiler).
- This document: **bd-cixqu.7.15** (G.12 operator-runbook).
- Proof assistant: **Lean 4 v4.7.0** (pinned). See
  [`docs/adr/ADR-0007-proof-assistant-selection.md`](../adr/ADR-0007-proof-assistant-selection.md).
- IFC strategy: [`docs/adr/ADR-0006-ifc-strategy-decision.md`](../adr/ADR-0006-ifc-strategy-decision.md).
- Proof bundle contract: [`docs/PROOF_ARTIFACT_CONTRACT_V1.md`](../PROOF_ARTIFACT_CONTRACT_V1.md).

## When proof-rebuild needs to run

Run the proof-rebuild gate whenever the source-of-truth for a proved
property changes. The five canonical triggers:

| Trigger | Why it forces a rebuild |
|---|---|
| Edit to a `.lean` proof file under `proofs/` | The proof body changed; the kernel must re-typecheck. |
| Edit to a statement file referenced by a proof | The theorem statement may no longer match its proof's conclusion. |
| Change to a Rust type whose Lean shadow appears in a statement | The Lean shadow can drift away from the Rust shape; the rebuild verifies the binding still typechecks. |
| Pinned Lean toolchain version bump | A new compiler version may reject a proof that the old one accepted (and vice versa). |
| New axiom added to the kernel | Any new axiom widens the trusted base; the operator must approve and the rebuild must succeed on the widened base. |

**Do not** rebuild "just to be safe" on every commit — proof rebuilds
are expensive and the gate stays green only when re-runs are
deterministic. Run the rebuild when a trigger fires; otherwise rely on
the gate's cached verdict.

## "The proof failed in CI — what does that mean?"

A CI proof failure is one of four distinct events. Read the gate's
`proof_failure_report.json` first; its `failure_class` field names
which event fired.

### Class 1 — `kernel_typecheck_failed`

The Lean kernel rejected a proof body. The proof itself is broken — a
tactic invocation no longer closes its goal, an automation hint became
stale, or a pattern match was made non-exhaustive by a constructor
addition.

**Unblock**:
1. Open the named proof file at the line in the failure report.
2. Run `lean --version` and confirm it is **v4.7.0** (the pinned
   version). A local toolchain drift is the single most common cause.
3. Read the goal at the failure point. If it has a new hypothesis the
   proof did not anticipate, you either accept it (extend the proof) or
   reject it (back out the source change that introduced it).
4. Do **not** add an `sorry` to the proof to unblock CI. The release
   gate refuses any proof bundle containing a `sorry`.

### Class 2 — `statement_diverged`

The Lean shadow of a Rust type or constant no longer matches its
upstream definition. The proof's theorem is still well-typed inside
Lean but no longer says anything meaningful about the runtime.

**Unblock**:
1. The failure report names the upstream Rust path and the Lean shadow
   path. Diff them.
2. If the Rust change was intentional, update the Lean shadow to match,
   then run the proof rebuild. If the rebuild passes, the shadow update
   was sound; if it fails with `kernel_typecheck_failed`, you broke the
   downstream proof and must fix it before merging.
3. If the Rust change was unintentional, revert the Rust change.

### Class 3 — `axiom_set_widened`

A new axiom appeared in the proof bundle's trusted base. The kernel
accepts the bundle, but the trust envelope is now wider than the last
released bundle's. The release gate refuses widening without explicit
operator approval.

**Unblock**:
1. The failure report names the new axiom(s) under
   `axiom_diff.added[]`.
2. For each added axiom, decide: does this axiom belong in the trusted
   base? An axiom that captures an external assumption (e.g. "the host
   CSPRNG is cryptographically secure") may be acceptable; an axiom
   that captures a proof gap (e.g. "the IFC lattice is non-interfering"
   when no proof has been built) is **not** acceptable.
3. Acceptable axioms: edit `proofs/axiom_manifest.json` to declare the
   new axiom, attach a rationale, and re-run. The release gate now
   compares against the widened-and-approved base.
4. Unacceptable axioms: prove them. Adding an axiom to silence a proof
   gap is the formal-methods equivalent of `unwrap()` on an `Option`.

### Class 4 — `kernel_timeout`

The kernel did not finish typechecking within the gate's budget. The
proof body is too slow to admit, OR a tactic is in an infinite
unification loop, OR the build host is under load.

**Unblock**:
1. Re-run on a quiet host first. If the second run finishes, the host
   was the cause and no action is needed beyond noting the flake.
2. If the second run also times out, the proof body itself is at
   fault. Common causes:
   - A `simp` invocation triggering an expensive rewrite normalization.
   - A `decide` tactic on a large finite domain.
   - A pattern unification loop in a recently-added lemma.
3. Refactor the proof to use targeted lemmas instead of large tactic
   blocks. Re-run.

## How to triage a proof-failure (generic procedure)

When the failure class is not obvious from the report, use this
procedure:

1. **Capture** the full `proof_failure_report.json` + the corresponding
   `events.jsonl` + the failing Lean file at the named line range. These
   three together are the triage packet.
2. **Reproduce locally**. Run the gate locally with the same Lean
   toolchain (`v4.7.0`) and the same source revision. A reproduction
   failure narrows the cause to the build host.
3. **Bisect** if the proof passed at the prior release-gate run. The
   commit range between the last-green run and the failing run names
   the offending change.
4. **Read** the goal state at the failure point. The Lean tactic-state
   dump in the failure report tells you exactly what hypotheses were
   in scope and what goal remained — most triages converge here.
5. **Escalate** to the Track G maintainers when:
   - The failure class is `axiom_set_widened` and the new axiom is
     architecturally significant.
   - The proof body looks unchanged and the kernel still rejects it.
   - The failure persists across multiple Lean toolchain versions.

## How to add a new lemma

The path from "I need a lemma that says X" to a green proof rebuild:

### Step 1 — Place the statement

Decide which file the lemma belongs in. The convention:

| Lemma scope | Lives under |
|---|---|
| Generic algebraic facts (about lists, finite sets, etc.) | `proofs/library/` |
| IFC lattice facts | `proofs/ifc/` |
| Capability-narrowing facts | `proofs/capabilities/` |
| Specific compile-correctness obligation | The proof file that consumes it |

Do **not** add facts to a generic library file unless they are
genuinely generic. A "lemma" that mentions a FrankenEngine-specific
type does not belong in `proofs/library/`.

### Step 2 — Write the statement first, body later

Open the chosen file. Add the new lemma's statement with `sorry` as the
body during local development:

```lean
theorem ifc_join_associative (a b c : Label) :
    join (join a b) c = join a (join b c) := by
  sorry
```

Run the kernel locally to confirm the statement typechecks. A
statement that does not typecheck cannot be a lemma; revise.

### Step 3 — Replace `sorry` with a real proof

Build the proof body. The release gate refuses any proof bundle that
contains a `sorry`, so this step is mandatory before opening a PR.

### Step 4 — Local verification

```bash
./scripts/run_rgc_proof_rebuild.sh ci
```

Confirm the gate emits:
- `proof_bundle/<hash>/` directory.
- `run_manifest.json` listing every checked file.
- `axiom_diff.json` whose `added` field is empty (you did not widen the
  trusted base by introducing your lemma).
- A green verdict in the events stream.

### Step 5 — Submit

The PR description should name the lemma, the file it landed in, and
why it is generic-enough or specific-enough for that location. Track G
review pays particular attention to lemma placement — a generic-looking
lemma in a specific file is often the wrong abstraction.

## Reading an SMT unsat-core output

Some proofs offload sub-goals to an SMT solver (typically Z3, in the
Lean SMT bridge). When SMT closes a goal, the proof bundle records the
**unsat core** — the minimal set of premises the solver used. The
unsat core is itself part of the trusted base.

To read it:

1. Open `proof_bundle/<hash>/smt_unsat_cores.json`.
2. Each entry binds an SMT call site to its unsat core. The core is a
   list of premise names, in the order the solver consumed them.
3. Cross-reference each premise to its definition in the Lean source.
   Premises that the proof author did not declare-as-trusted should
   not appear in the core. A surprise premise is a proof-economy bug:
   the solver is leaning on an assumption the author did not intend.
4. The unsat core is **stable per Z3 version**. A core that changes
   under a Z3 bump must be re-reviewed; the new core may rely on
   premises that were never approved.

If you see a premise in an unsat core that looks like a runtime
constant (e.g. an integer chosen by the harness, a string literal
specific to a test fixture), the proof has leaked a non-mathematical
fact into the trusted base. File a bead.

## How to read a proof bundle

A proof bundle is the artifact a green proof rebuild emits. Its layout:

```
proof_bundle/<content-hash>/
├── run_manifest.json          # schema id, host facts, content hashes, replay commands
├── trace_ids.json             # UUIDv7 trace / decision / policy ids
├── events.jsonl               # structured event stream (one event per checked file)
├── commands.txt               # verbatim shell transcript for replay
├── axiom_manifest.json        # declared axioms + rationales
├── axiom_diff.json            # diff vs the last released bundle (added / removed)
├── smt_unsat_cores.json       # one entry per SMT call site
├── lemma_inventory.json       # every lemma the bundle proves, by location + statement hash
└── checked_files.txt          # ordered list of every .lean file the kernel admitted
```

Operator reading order:

1. **`run_manifest.json`** — confirms the bundle is for the Lean
   toolchain you expect (`lean_version: "4.7.0"`). A bundle from a
   different toolchain is not comparable with the released bundle.
2. **`axiom_diff.json`** — the trust-envelope diff. An `added` list
   that is non-empty means the released claim now rests on premises
   the prior bundle did not. Approve or reject.
3. **`lemma_inventory.json`** — every lemma the bundle proves.
   Cross-check against the claim-to-proof matrix
   ([`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md))
   to confirm every claim that names this bundle is actually backed
   here.
4. **`smt_unsat_cores.json`** — the SMT trust diff. Same review shape
   as the axiom diff.
5. **`events.jsonl`** — for an audit trail, the per-file kernel
   verdicts and timing data.
6. **`commands.txt`** — for replay verification.

## Cross-references

- [`docs/PROOF_ARTIFACT_CONTRACT_V1.md`](../PROOF_ARTIFACT_CONTRACT_V1.md) —
  the proof-bundle schema, the source of truth for the layout above.
- [`docs/adr/ADR-0007-proof-assistant-selection.md`](../adr/ADR-0007-proof-assistant-selection.md) —
  why Lean 4 v4.7.0 is the pinned toolchain.
- [`docs/adr/ADR-0006-ifc-strategy-decision.md`](../adr/ADR-0006-ifc-strategy-decision.md) —
  the IFC-strategy decision the proofs implement.
- [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md) —
  every claim names a backing bundle; the bundle's `lemma_inventory.json`
  must satisfy that backing relation.
- [`RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md) — the broader
  RGC gate catalogue.
- [`ADDING_A_NEW_CAPABILITY.md`](./ADDING_A_NEW_CAPABILITY.md) +
  [`INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`](./INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md) —
  sibling operator runbooks that mirror this document's "read the
  diagnostic / decide / act / verify" shape.
