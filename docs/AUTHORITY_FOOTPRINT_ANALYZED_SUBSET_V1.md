# Authority-Footprint Analyzer — Analyzed-Subset Boundary (v1)

> Owning beads: `bd-fqlfw.5.1` (E5.T1, the `frankenctl check` analyzer) and
> `bd-fqlfw.5.4` (E5.T4, wording/soundness discipline).
> Implementation: `crates/franken-engine/src/authority_footprint.rs`.

## What this document fixes

`frankenctl check <file>` reports an **inferred authority footprint for the
SUPPORTED syntax of the file**. A source-level "authority footprint" is easy to
misread as a complete security type-checker. Under this project's
claims-bounded-by-evidence brand (`docs/RUNTIME_CHARTER.md` §7), the analyzer
must never assert more than it can back. This document states exactly what the
analyzer covers, where it stops, and the wording it is allowed to use.

## Soundness posture: binary, never heuristic

The analyzer shares a single source of truth with the runtime enforcer: it runs
`lowering_pipeline::lower_ir0_to_ir3` — the *same* lowering the runtime executes.
It therefore makes exactly two kinds of statement:

1. A **definite** finding — the runtime enforcer makes the identical
   determination from the same lowering. Every emitted finding carries
   `confidence = "definite"` (`FindingConfidence::Definite`). The analyzer never
   emits a low-confidence or heuristic guess.
2. **Fail-closed** — when it cannot lower a construct, it refuses to assert a
   footprint for that construct rather than guessing. This is surfaced
   explicitly (see *Completeness* below), never silently passed.

Because a wrong diagnostic could only arise from the lowering pipeline that the
runtime itself uses, a wrong diagnostic is a UX bug, not a soundness regression:
the analyzer and the enforcer cannot disagree about a supported construct.

## Completeness marker (`analysis_completeness`)

Every report carries an explicit `analysis_completeness`:

| Value | Meaning |
|---|---|
| `complete` | The whole file lowered to IR2. The footprint is exhaustive **for the supported syntax of this file**. |
| `bounded_at_first_violation` | Lowering fail-closed at the **first** ambient-authority access. Constructs *after* that point were **not** analyzed. Resolve the reported access and re-run to surface any further footprint. |
| `unanalyzable` | The file could not be analyzed at all (parse error or unsupported construct). **No footprint is asserted.** |

The `bounded_at_first_violation` state exists because lowering applies a
deny-by-default (empty) ambient-authority profile and returns at the first raw
ambient access (`eval`, `process[.env]`, `require`, `fetch`, `crypto`, …). v1 of
the file-level analyzer therefore surfaces one ambient violation per pass; the
report and the least-authority suggestion both say so, so the count is never
read as "only one exists".

## What is analyzed

For a file that lowers cleanly (`complete`):

- **Minimal capability footprint** — the capability tags the supported hostcall
  edges require (`Ir2Op.required_capability`), each with the exact source
  locations (spans) that demand them, plus a best-effort typed
  `RuntimeCapability`.
- **IFC findings** — denied flows (`error[FE-CAP-0002]`) and
  required-declassification obligations (`error[FE-CAP-0003]`) from the IR2
  flow-proof artifact, projected back onto the emitting op's span.

For a file that hits the ambient boundary (`bounded_at_first_violation`):

- The first ambient-authority access as `error[FE-CAP-0001]`, with the accessor
  as written in source, its span, and the implied `RuntimeCapability` a grant
  would need to mediate it.

## What is NOT analyzed (the boundary)

The analyzer fails closed — it asserts nothing — for:

- **Parse errors** (e.g. unterminated string literals, empty binding patterns).
- **Unsupported constructs** that the lowering pipeline rejects (anything the
  IR0→IR3 pipeline does not yet lower; tracked in `lowering_gap_inventory.rs`).
- **Anything after the first ambient-authority violation** in a pass (the
  lowering returns at that point).

Bare-identifier ambient accessors (e.g. `eval`, `fetch`, `process` used as plain
identifiers) carry no source span yet (`bd-fqlfw.1.1`); their findings are still
emitted but with `location = null`. Spans for member accesses
(`process.env`, `globalThis.require`, …) are statement-granular today.

## Wording contract

- The report's `disclaimer` is frozen (golden-tested): *"inferred authority
  footprint for SUPPORTED syntax; not a proof of noninterference for arbitrary
  JS/TS. Unanalyzable constructs fail closed."*
- No dynamic output (finding messages, the least-authority suggestion, or a
  fail-closed reason) may positively assert a noninterference proof for
  arbitrary JS/TS or use absolute-superiority language. This is enforced by the
  `no_dynamic_output_overclaims_a_noninterference_proof` test.

## Determinism

The report is a pure function of `(source, source_label, parse_goal)` — it
carries no wall-clock or host facts — so `frankenctl check --format json` is
byte-deterministic and content-addressed via `report_sha256` (SHA-256 over the
canonical body with that field blank). `--out <dir>` writes a
`run_manifest.json` + `events.jsonl` bundle that is replay-stable.

## Exit codes

| Code | Outcome |
|---|---|
| `0` | analyzed cleanly, no findings |
| `1` | analyzed, authority/IFC findings present |
| `2` | unanalyzable (parse error / unsupported construct) — fail-closed |
