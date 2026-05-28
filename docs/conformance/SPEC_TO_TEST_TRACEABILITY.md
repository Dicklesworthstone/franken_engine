# ECMA-262 ES2020 — Spec-to-Test Traceability Matrix

> Closes audit findings **FIND-13** (`bd-04uo3`) and **FIND-25**
> (`bd-euwqz`). Sibling docs:
> - Spec pin: [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md)
> - Coverage shape: [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md)
> - Per-harness manifest: [`crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md`](../../crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md)

This matrix answers the per-clause inverse lookup **"which test cases
cover ECMA-262 §X.Y.Z?"** that ScarletJay's audit (`bd-85qfs`) flagged
as unanswerable.

## How this matrix is generated

Until a compliance-report-generator binary lands (`bd-13rib` / FIND-20),
this matrix is **hand-extracted** from the harness sources by
regex-scanning each `tests/*_test262_conformance.rs` file for a
clause-tag field on every test-case struct literal, then aggregating
by §-section. The exact extraction (rerun on every doc update):

```python
import os, re, collections
section_map = collections.defaultdict(lambda: collections.defaultdict(list))
for h in sorted(f for f in os.listdir('tests/') if 'test262' in f
                and 'conformance' in f and f.endswith('.rs')):
    src = open(f'tests/{h}').read()
    h_short = h.replace('_test262_conformance.rs', '')
    # Field name drifts across harnesses (FIND-12 bd-cd0px):
    for fld in ('es_section', 'es2020_section', 'spec_section'):
        for m in re.finditer(rf'{fld}:\s*"([^"]+)"', src):
            window = src[max(0,m.start()-400):m.end()+400]
            level_m = re.search(r'requirement_level:\s*RequirementLevel::(\w+)',
                                window)
            id_m = re.search(r'id:\s*"([^"]+)"', window)
            section_map[m.group(1)][h_short].append(
                (id_m.group(1) if id_m else None,
                 level_m.group(1) if level_m else '?'))
```

Staleness is a bug to file against this document.

## Headline counts (HEAD at commit time)

| Metric | Value |
| --- | ---: |
| Harnesses with clause tags | **9** of 11 |
| Distinct §-sections covered | **53** |
| Total tagged test cases | **157** |
| `MUST` cases | **90** |
| `SHOULD` cases | **1** |
| Cases without a resolvable `requirement_level` | **66** |

The 66 cases without a resolvable level are an artefact of the
field-name drift documented under FIND-12 (`bd-cd0px`): the
`iteration_statements`, `template_literal`, and `strict_mode` harnesses
use struct shapes that put `requirement_level` outside the 400-char
window the extractor searches, or omit the field entirely.

## Field-name drift across harnesses (confirms FIND-12)

The same logical attribute ("which ECMA-262 §-section does this case
anchor against?") appears under **three different field names**:

| Harness | Field name used |
| --- | --- |
| `abstract_operations` | `es_section` |
| `async_promise` | `es_section` |
| `arrow_function` | `es2020_section` |
| `destructuring_binding` | `es2020_section` |
| `iterator_protocol` | `es2020_section` |
| `optional_chaining` | `es2020_section` |
| `strict_mode` | `es2020_section` |
| `iteration_statements` | `spec_section` |
| `template_literal` | `spec_section` |
| `test262_conformance_runner_integration` | (no tags — runner suite) |
| `test262_runner_conformance_golden` | (no tags — runner golden) |

A unification pass to a single canonical field name (recommended:
`es2020_section`, the most-used variant) would let
`crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md` cite a
single load-bearing tag in its scorecard generator. That unification
is the deliverable for FIND-12 (`bd-cd0px`) and is **not** carried by
this matrix.

## The matrix (§-section → covering test ids)

Sections are sorted in canonical ECMA-262 order (numeric tuple).
`level` is the case's `RequirementLevel` when the extractor could resolve
it. `?` means the case is tagged with a §-section but the level field
either uses a non-enum encoding or is absent.

| §-section | Harness | Level | Test cases |
| --- | --- | --- | --- |
| §7.1.1 (ToBoolean) | `abstract_operations` | MUST×3 | `ES2020-7.1.1-toboolean-zero-is-false`; `…empty-string-is-false`; `…nonempty-string-is-true` |
| §7.1.4 (ToNumber) | `abstract_operations` | MUST×2 | `ES2020-7.1.4-tonumber-string-numeric`; `…boolean-true` |
| §7.2.14 (AbstractEquality) | `abstract_operations` | MUST×1 | `ES2020-7.2.14-abstract-equality-coerces-string-number` |
| §7.2.15 (StrictEquality) | `abstract_operations` | MUST×3 | `ES2020-7.2.15-strict-equality-no-coercion`; `…nan-not-equal-to-itself`; `…positive-zero-strictly-equals-negative-zero` |
| §7.4.1 (GetIterator) | `iterator_protocol` | MUST×2 | `ES2020-7.4.1-get-iterator-operation`; `…symbol-iterator-not-callable` |
| §7.4.2 (IteratorNext) | `iterator_protocol` | MUST×1 | `ES2020-7.4.2-iterator-next-throws` |
| §7.4.6 (IteratorClose) | `iterator_protocol` | MUST×1 | `ES2020-7.4.6-iterator-close-return` |
| §8.1.1.2.1 (Strict declaration / `with` ban) | `strict_mode` | ?×2 | `ES2020-8.1.1.2.1-undeclared-assignment-global-strict`; `…function-strict` |
| §8.4.1 (Microtask queue) | `async_promise` | MUST×2 | `ES2020-8.4.1-microtask-runs-after-script-sync`; `…settimeout-runs-after-microtask-checkpoint` |
| §10.2.1 (Strict mode directive) | `strict_mode` | ?×3 | `ES2020-10.2.1-directive-string-literal`; `…function-scope`; `test-directive` |
| §10.2.1.1 (Strict `this`) | `strict_mode` | ?×2 | `ES2020-10.2.1.1-this-undefined-function-call`; `…strict-directive` |
| §11.8.3 (Numeric literals — strict legacy octal ban) | `strict_mode` | ?×2 | `ES2020-11.8.3-octal-literal-global-strict`; `…function-strict` |
| §11.8.6 (Template literal lexical) | `template_literal` | ?×4 | `template-literal-escape-backslash` + 3 more |
| §12.2.9 (TemplateLiteral semantics) | `template_literal` | ?×12 | `template-literal-basic-empty` + 11 more |
| §12.3.2.1 (OptionalExpression) | `optional_chaining` | MUST×17 SHOULD×1 | `ES2020-12.3.2.1-basic-property-access` + 17 more |
| §12.3.6.1 (Spread in call) | `iterator_protocol` | MUST×1 | `ES2020-12.3.6.1-spread-array` |
| §12.5.4 (`void` operator) | `abstract_operations` | MUST×1 | `ES2020-12.5.4-void-always-undefined` |
| §12.5.4.2 (`delete` in strict mode) | `strict_mode` | ?×2 | `ES2020-12.5.4.2-delete-identifier-global-strict`; `…function-strict` |
| §12.5.5 (`typeof`) | `abstract_operations` | MUST×2 | `ES2020-12.5.5-typeof-undefined`; `…typeof-null-is-object` |
| §12.15.5 (Destructuring assignment + iterator) | `iterator_protocol` | MUST×1 | `ES2020-12.15.5-destructuring-iterator` |
| §13.2.2 (do-while) | `iteration_statements` | ?×2 | `do-while-statement-basic`; `…single-iteration` |
| §13.2.3 (while) | `iteration_statements` | ?×3 | `while-statement-basic`; `…complex-condition`; `…empty-body` |
| §13.2.4 (for) | `iteration_statements` | ?×8 | `for-statement-basic` + 7 more |
| §13.2.5 (for-in) | `iteration_statements` | ?×3 | `for-in-statement-basic`; `…var-declaration`; `…let-declaration` |
| §13.2.6 (for-of) | `iteration_statements` | ?×11 | `for-of-statement-basic` + 10 more |
| §13.3.3 (Destructuring binding patterns) | `arrow_function` + `destructuring_binding` | MUST×3 | `ES2020-13.3.3-array-destructuring`; `…object-destructuring`; `…invalid-numeric-lvalue` |
| §13.3.3.6 (Array binding) | `destructuring_binding` | MUST×4 | `ES2020-13.3.3-array-basic` + 3 more |
| §13.3.3.7 (Array binding — rest) | `destructuring_binding` | MUST×5 | `ES2020-13.3.3-array-rest` + 4 more |
| §13.7.5.15 (for-of iteration) | `iterator_protocol` | MUST×1 | `ES2020-13.7.5.15-for-of-basic` |
| §13.11.1 (`with` statement — strict ban) | `strict_mode` | ?×2 | `ES2020-13.11.1-with-statement-global-strict`; `…function-strict` |
| §13.12 (break) | `iteration_statements` | ?×4 | `break-statement-for-loop` + 3 more |
| §13.13 (continue) | `iteration_statements` | ?×4 | `continue-statement-while-loop` + 3 more |
| §14.1.2 (Duplicate param — strict ban) | `strict_mode` | ?×2 | `ES2020-14.1.2-duplicate-param-global-strict`; `…function-strict` |
| §14.1.19 (Default params) | `arrow_function` | MUST×2 | `ES2020-14.1.19-default-params`; `…default-params-override` |
| §14.1.20 (Rest params / patterns) | `arrow_function` + `destructuring_binding` | MUST×3 | `ES2020-14.1.20-rest-params`; `…parameter-object-pattern`; `…parameter-array-pattern` |
| §14.2.1 (ArrowFunction grammar) | `arrow_function` | MUST×12 | `ES2020-14.2.1-basic-arrow` + 11 more |
| §14.2.16 (Arrow lexical `this`) | `arrow_function` | MUST×2 | `ES2020-14.2.16-lexical-this`; `…arrow-in-method` |
| §14.7 (Async arrow) | `arrow_function` | MUST×2 | `ES2020-14.7-async-arrow`; `…async-arrow-params` |
| §15.8 (Async function semantics) | `async_promise` | MUST×2 | `ES2020-15.8-async-function-wraps-return-in-promise`; `…throw-becomes-rejection` |
| §15.8.4 (await) | `async_promise` | MUST×2 | `ES2020-15.8.4-await-rejected-promise-propagates-to-caller`; `…assimilates-thenable` |
| §22.1.2.1 (`Array.from`) | `iterator_protocol` | MUST×1 | `ES2020-22.1.2.1-array-from-iterator` |
| §25.1.1.1 (Iterator interface) | `iterator_protocol` | MUST×1 | `ES2020-25.1.1.1-iterator-interface-next` |
| §25.1.1.2 (IteratorResult) | `iterator_protocol` | MUST×1 | `ES2020-25.1.1.2-iterator-result-interface` |
| §25.6.1.3 (`Promise.resolve` thenable assimilation) | `async_promise` | MUST×1 | `ES2020-25.6.1.3-promise-resolve-thenable-enqueues-nested-microtask` |
| §25.6.1.9 (Unhandled rejection) | `async_promise` | MUST×1 | `ES2020-25.6.1.9-unhandled-rejection-does-not-block-microtasks` |
| §25.6.4.1 (`Promise.all`) | `async_promise` | MUST×1 | `ES2020-25.6.4.1-promise-all-aggregates-fulfillments` |
| §25.6.4.2 (`Promise.allSettled` — ES2020) | `async_promise` | MUST×1 | `ES2020-25.6.4.2-promise-allsettled-preserves-status-and-order` |
| §25.6.4.3 (`Promise.race`) | `async_promise` | MUST×1 | `ES2020-25.6.4.3-promise-race-uses-first-settled-input` |
| §25.6.4.4 (`Promise.reject`) | `async_promise` | MUST×1 | `ES2020-25.6.4.4-reject-catch-propagates-reason` |
| §25.6.4.5 (`Promise.resolve`) | `async_promise` | MUST×1 | `ES2020-25.6.4.5-resolve-then-identity` |
| §25.6.5.1 (`Promise.prototype.then`) | `async_promise` | MUST×1 | `ES2020-25.6.5.1-then-error-routed-to-catch` |
| §25.6.5.4 (Promise chaining) | `async_promise` | MUST×2 | `ES2020-25.6.5.4-multiple-microtasks-fifo`; `…chained-then-propagates-return-value` |
| §27.2.4.5 | `async_promise` | MUST×2 | **`ES2022-27.2.4.5-promise-any-fulfills-with-first-fulfillment`**; **`…all-rejected-aggregate-errors`** ⚠ |

⚠ The two `§27.2.4.5` cases carry an **`ES2022-…`** test-id prefix
(not `ES2020-`), meaning they assert `Promise.any` — a feature
introduced in **ES2021**, not in the pinned ES2020 profile. Per the
spec-pin doc, post-ES2020 features are out of scope; these cases
should either be: (a) moved into a sibling `*_post_es2020_conformance`
harness, or (b) recorded as a documented divergence in
`crates/franken-engine/tests/ECMA262_DISCREPANCIES.md` (FIND-4
`bd-w50mz`). Filed as a follow-up note on this matrix until a sibling
bead opens.

## Inverse map (harness → §-sections owned)

| Harness | §-section ownership |
| --- | --- |
| `abstract_operations` | §7.1.1; §7.1.4; §7.2.14; §7.2.15; §12.5.4; §12.5.5 |
| `arrow_function` | §13.3.3; §14.1.19; §14.1.20; §14.2.1; §14.2.16; §14.7 |
| `async_promise` | §8.4.1; §15.8; §15.8.4; §25.6.1.3; §25.6.1.9; §25.6.4.1–§25.6.4.5; §25.6.5.1; §25.6.5.4; **§27.2.4.5 (post-ES2020)** |
| `destructuring_binding` | §13.3.3; §13.3.3.6; §13.3.3.7; §14.1.20 |
| `iteration_statements` | §13.2.2; §13.2.3; §13.2.4; §13.2.5; §13.2.6; §13.12; §13.13 |
| `iterator_protocol` | §7.4.1; §7.4.2; §7.4.6; §12.3.6.1; §12.15.5; §13.7.5.15; §22.1.2.1; §25.1.1.1; §25.1.1.2 |
| `optional_chaining` | §12.3.2.1 |
| `strict_mode` | §8.1.1.2.1; §10.2.1; §10.2.1.1; §11.8.3; §12.5.4.2; §13.11.1; §14.1.2 |
| `template_literal` | §11.8.6; §12.2.9 |
| `test262_conformance_runner_integration` | (runner-level; no clause anchor by design) |
| `test262_runner_conformance_golden` | (output golden; no clause anchor by design) |

## Cross-references

- Spec pin & in-/out-of-scope: [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md).
- Aggregate scorecard shape: [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md).
- Manifest + per-target scorecard: [`crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md`](../../crates/franken-engine/docs/CONFORMANCE_HARNESS_MANIFEST.md).
- Documented intentional divergences: [`crates/franken-engine/tests/ECMA262_DISCREPANCIES.md`](../../crates/franken-engine/tests/ECMA262_DISCREPANCIES.md).
- Test262 fixture pin: [`crates/franken-engine/tests/test262_conformance_pins.toml`](../../crates/franken-engine/tests/test262_conformance_pins.toml).
- Follow-up: compliance-report generator → `bd-13rib` (FIND-20).
- Follow-up: tag-field unification → `bd-cd0px` (FIND-12).
- Follow-up: `strict_mode` empty `es2020_section` tags → `bd-s2ubw` (FIND-15).
