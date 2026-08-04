# DW Documentation & Operator-Enablement Standard (bd-fqlfw.12 / DW.DOCS)

> The shared documentation contract for every user-facing Dueling-Wizards capability.
> Sibling of [DW.STD](DW_TESTING_AND_VERIFICATION_STANDARD.md): **DW.STD proves a capability
> *works*; DW.DOCS makes it *usable*.** Every `E*.DOC` task references this document.
>
> **Why this exists.** The repo serves several audiences (security researcher / operator /
> contributor / downstream consumer / benchmarker / AI agent) through an audience-segmented
> README + 672 docs + `runbooks/`. A capability that ships with no docs/runbook does not
> "work for users" — operators can't adopt it, downstream consumers can't rely on it, and AI
> agents can't drive it. This standard makes documentation a first-class, gated deliverable.

## Shipped templates (use them)

| Template | Copy to | Purpose |
|---|---|---|
| [`templates/operator_runbook.md.template`](templates/operator_runbook.md.template) | `runbooks/dw_<cap>.md` | Preflight, normal use, failure triage, how to read the bundle. |
| [`templates/readme_section.md.template`](templates/readme_section.md.template) | a section in `README.md` under the right audience guide | What it does, when to use it, a copy-pasteable example. |
| [`templates/contributor_guide.md.template`](templates/contributor_guide.md.template) | `docs/dueling_wizards/contributing/<cap>.md` | "How to extend X" with a worked example (contributor-facing capabilities, e.g. E4). |

## Mandatory doc deliverables (every user-facing capability)

1. **README section** under the correct audience reading-guide entry: what the capability
   does, when to use it, and a copy-pasteable example. De-slopified, precise prose; **no
   absolute-superiority terms** (`guarantees` / `unbreakable` / `always` / `proves` /
   `category-defining` / `>=Nx faster` without artifacts) — the claim gate forbids them.
2. **Operator runbook** in `runbooks/`: preflight checklist; normal-use walkthrough; failure
   triage (what each non-zero exit code and each degraded-mode receipt means and how to
   recover); and how to read the emitted artifact bundle (which file answers which question).
3. **Runnable example** under `examples/` following the numbered-demo convention, paired with
   its operator binary where one exists; the example must actually run and emit its artifact.
4. **`--help` text** with runnable examples and documented exit codes (overlaps DW.STD CLI
   ergonomics; the doc task verifies it exists and is accurate).
5. **Claim-state disclosure**: where the capability makes a claim, document its current matrix
   state (OBSERVED / TARGETED / HYPOTHESIS) and bounded wording, so a reader never over-trusts.
6. **Doc-drift guard**: any doc that quotes a CLI surface, an exit code, or a claim state is
   checked against reality (the repo gates prose). Prefer generating reference tables from the
   source of truth. Minimum bar: the capability's `E*.DOC` task adds a check (a small script or
   a test) that greps the documented exit codes / subcommands / claim IDs and fails if they do
   not match the shipped gate script, `--help`, and `docs/claim_to_proof_matrix_v1.json`.

## Contributor docs

For contributor-facing capabilities (notably **E4 intrinsic table**), add a CONTRIBUTING-style
"how to add X" guide with a fully worked example. This is itself an agent-ergonomics
deliverable: the easier it is for a human or agent to extend the capability, the faster the
project's language/coverage surface grows.

## Done when

A new operator or AI agent can adopt the capability end-to-end **from the docs alone**, without
reading source, and the docs cannot silently drift from the shipped behavior.

## Per-capability doc tasks (gated on each capability's `E*.TEST` capstone)

| Task | Capability | Emphasis |
|---|---|---|
| `bd-fqlfw.2.9` | Differential Oracle | divergence taxonomy + denominator/fairness manifest + degraded receipt |
| `bd-fqlfw.3.7` | Flight Recorder + debugger | which bundle file answers which question; `--robot` agent loop |
| `bd-fqlfw.4.7` | Intrinsic Table | **contributor guide**: add a builtin via one row + one impl fn |
| `bd-fqlfw.5.6` | Authority/Intake analyzer | reading the footprint; editor/LSP setup; bounded-claim note |
| `bd-fqlfw.6.7` | Proof-Spine | claim states (Unavailable/FixtureOnly/Unknown/Counterexample/Proven) |
| `bd-fqlfw.7.7` | Conformance Frontier | weighted views; summary-not-proof; the ranked worklist |
| `bd-fqlfw.8.8` | Non-Use Certificate | integrator guide + **the explicit threat-model/analyzed-subset boundary** |
