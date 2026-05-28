# ECMA-262 Conformance Targets (FrankenEngine)

> **Status:** Anchored. This document is the single source of truth for FrankenEngine's
> ECMA-262 conformance scope. Every test262 conformance harness in
> `crates/franken-engine/tests/*_test262_conformance.rs` is measured against the
> edition and clause space declared here.
>
> **Tracking beads:** bd-5kg0h (FIND-1 — spec pin), bd-d9ot3 (FIND-18 — scope inclusions/exclusions).
> Parent audit epic: bd-85qfs.

## 1. Specification target

| Field | Value |
| --- | --- |
| Specification | ECMA-262, Edition 11 (ES2020) |
| Spec URL | <https://tc39.es/ecma262/2020/> |
| Test suite | TC39 test262 |
| Test262 source repo | <https://github.com/tc39/test262> |
| Test262 commit (pinned) | `d0c1b4555b03dd404873fd6422a4b5da00136500` |
| Pin file (immutable) | [`crates/franken-engine/tests/test262_conformance_pins.toml`](tests/test262_conformance_pins.toml) |

The `test262_commit` value above MUST match `test262_conformance_pins.toml::test262_commit`.
The pin file is the immutable anchor; if the two disagree, the pin wins, and a
follow-up commit MUST reconcile this document.

## 2. In-scope clause space (normative)

In scope: every normative clause of ECMA-262 Edition 11, sections §1 through §28
that is *not* listed under §3 below.

In particular the following clause classes are **in scope**:

- §6 ECMAScript Data Types and Values (primitive coercion, ToBoolean/ToNumber/ToString/ToObject, …)
- §7 Abstract Operations
- §8 Executable Code and Execution Contexts (lexical environments, realms, …)
- §9 Ordinary and Exotic Objects Behaviours (ordinary internal methods, proxies)
- §10 ECMAScript Language: Source Code (strict mode rules, hoisting)
- §11 ECMAScript Language: Lexical Grammar (line terminators, identifier names, punctuators)
- §12 ECMAScript Language: Expressions
- §13 ECMAScript Language: Statements and Declarations (iteration, control flow, declarations)
- §14 ECMAScript Language: Functions and Classes
- §15 ECMAScript Language: Scripts and Modules (module records, top-level await is **out** — added post-ES2020)
- §18 The Global Object
- §19 Fundamental Objects (Object, Function, Boolean, Symbol, Error)
- §20 Numbers and Dates (Number, BigInt, Math, Date)
- §21 Text Processing (String, RegExp)
- §22 Indexed Collections (Array, TypedArray)
- §23 Keyed Collections (Map, Set, WeakMap, WeakSet)
- §24 Structured Data (ArrayBuffer, SharedArrayBuffer, DataView, JSON, Atomics)
- §25 Control Abstraction Objects (Iterator, AsyncIterator, Generator, AsyncGenerator, Promise)
- §26 Reflection (Reflect, Proxy)
- §27 Memory Model

Every test case in a `*_test262_conformance.rs` harness MUST tag its `es_spec_section`
field with the §-prefixed section number from the in-scope list above
(see FIND-12 / bd-cd0px for the consistency rule).

## 3. Out-of-scope clauses (intentional exclusions)

The following clause classes are **intentionally out of scope** for the
ES2020 conformance target. They MUST NOT count against the MUST/SHOULD coverage
denominator; harnesses MAY ship a stub case that asserts the feature parses or
fails-closed, but those cases MUST be tagged with the exclusion reason below.

| Out-of-scope | Reason | Reviewed |
| --- | --- | --- |
| §A Annex A: Grammar Summary | Non-normative grammar restatement | 2026-05-28 |
| §B Annex B: Additional ECMAScript Features for Web Browsers | Web-host-only; FrankenEngine is a server-side runtime | 2026-05-28 |
| ECMA-402 (Internationalization API) | Separate standard, not part of ECMA-262 | 2026-05-28 |
| Top-level `await` in modules | Stage-3 at ES2020 freeze; promoted in ES2022 | 2026-05-28 |
| `WeakRef` (§26.2) and `FinalizationRegistry` (§26.3) | Stage-3 at ES2020 freeze; promoted in ES2021 | 2026-05-28 |
| `Promise.any` (§25.6.4.2 in ES2021) | Added post-ES2020 | 2026-05-28 |
| Logical assignment operators (`&&=`, `\|\|=`, `??=`) | Added in ES2021 | 2026-05-28 |
| Numeric separators in literals | Added in ES2021 | 2026-05-28 |
| `String.prototype.replaceAll` | Added in ES2021 | 2026-05-28 |
| Any other clause introduced after ES2020 (Edition 12+) | Outside the pinned edition | 2026-05-28 |

If a test262 case targets one of the above out-of-scope clauses, it MUST be
recorded in `test262_conformance_waivers.toml` with the reason
`out-of-scope-for-es2020`.

## 4. Conformance promotion thresholds

The thresholds below are normative for the "Conformant" promotion verdict.
Any score below the threshold MUST be reported as **Partial conformance** in
all status pages and release notes (this matches `docs/CONFORMANCE_HARNESS_MANIFEST.md`).

| Surface | MUST coverage | MUST pass rate | SHOULD coverage | SHOULD pass rate | Divergences |
| --- | --- | --- | --- | --- | --- |
| ECMAScript baseline builtins | ≥ 95% | ≥ 95% | ≥ 70% | ≥ 80% | All ACCEPTED in `ECMA262_DISCREPANCIES.md` |
| Replay receipt schemas | 100% | 100% | n/a | n/a | All ACCEPTED |
| Policy decision tables | 100% | ≥ 95% | n/a | n/a | All ACCEPTED |
| Artifact bundle manifests | 100% | 100% | n/a | n/a | None |

Current status (as of bd-85qfs audit, 2026-05-28): ECMAScript baseline builtins is at
**Partial conformance — MUST coverage 0.08, MUST pass rate on tested cases 0.84**
(147 tested, 124 passing of an estimated 1847 MUST clauses per
`docs/CONFORMANCE_HARNESS_MANIFEST.md` Compliance Scorecard).

## 5. Pin refresh policy

The `test262_commit` pin in `test262_conformance_pins.toml` MUST be refreshed
according to the following policy (tracked separately under bd-rpimp / FIND-23):

- **Quarterly cadence**, aligned with TC39 release cycle reviews (February / July / September).
- **Out-of-band refreshes** are allowed for spec corrections that affect existing test cases.
- Every refresh MUST:
  1. Bump `test262_commit` in the pin file.
  2. Regenerate test case vectors via `franken_test262_generator`.
  3. Re-run every `*_test262_conformance.rs` harness against the new pin.
  4. Update `ECMA262_DISCREPANCIES.md` if newly accepted divergences appear.
  5. Update the Compliance Scorecard row in `docs/CONFORMANCE_HARNESS_MANIFEST.md`.
  6. Land a single commit containing all of the above, with diff-review evidence
     attached to the PR description.

A refresh that changes pass/fail outcomes on already-tested cases is a
**reviewable event**, not a silent change.

## 6. Where this document is consumed

This document is the upstream reference for:

- `crates/franken-engine/tests/ECMA262_DISCREPANCIES.md` — every intentional divergence
  cites this document for the in-scope/out-of-scope decision.
- `crates/franken-engine/tests/test262_conformance_pins.toml` — the `es_profile`
  field MUST equal `"ES2020"` and the `test262_commit` field MUST match §1 above.
- `crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md` Compliance Scorecard —
  the "Spec Surface" row labelled "ECMAScript baseline builtins" implies the
  scope and thresholds declared here.
- `scripts/run_test262_es2020_gate.sh` — the gate script's exit code is meaningful
  only relative to the pin in §1 and the scope in §2 / §3.
- Every `*_test262_conformance.rs` harness — `es_spec_section` values are
  cross-checked against the in-scope clause classes in §2.

## 7. Change control

Any change to the in-scope clause space (§2) or the out-of-scope list (§3) is a
**spec-target change**. It MUST:

1. Land via a PR explicitly tagged `conformance-target-change`.
2. Update §1.6 Pin refresh policy if it implies a non-cosmetic regeneration.
3. Trigger a re-run of every `*_test262_conformance.rs` harness against the
   updated scope, with diff-review evidence attached to the PR.

Cosmetic edits to wording, link fixes, or typo corrections do not require the
above process.
