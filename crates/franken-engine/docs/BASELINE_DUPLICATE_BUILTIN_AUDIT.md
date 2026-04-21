# Baseline Interpreter Duplicate Builtin Dispatch Audit

**Last Updated:** 2026-04-20  
**File:** `crates/franken-engine/src/baseline_interpreter.rs`  
**Status:** Resolved for string-keyed builtin dispatch arms

## Scope

This audit tracks duplicate string-keyed builtin dispatch arms in
`InterpreterCore::dispatch_builtin_hostcall`, using exact capability strings such
as `"builtin:StringPrototypeToLowerCase" =>`.

It does not count test references, builtin-id mapping entries, comments, or
`BuiltinId` enum mentions. Those can legitimately appear multiple times while
all runtime dispatch still routes through a single canonical arm.

## Current Result

The current baseline interpreter has no duplicate string-keyed builtin dispatch
arms.

Verification script:

```bash
python3 - <<'PY'
from collections import Counter
from pathlib import Path
import re

counts = Counter()
for line in Path("crates/franken-engine/src/baseline_interpreter.rs").read_text().splitlines():
    match = re.match(r'\s+"(builtin:[^"]+)"\s*=>', line)
    if match:
        counts[match.group(1)] += 1

print(sum(counts.values()), len(counts), sum(1 for count in counts.values() if count > 1))
for capability, count in sorted(counts.items()):
    if count > 1:
        print(count, capability)
PY
```

Expected output:

```text
186 186 0
```

## Consolidated Coverage

The original audit identified 52 duplicated capability strings across more than
100 duplicate dispatch arms. Those runtime duplicates have since been collapsed
into single canonical arms. Representative covered groups include:

- String casing and locale casing aliases.
- `String.prototype.endsWith`, `charAt`, and adjacent string helpers.
- Array mutation/search/iterator helpers.
- Object introspection helpers.
- Math trigonometric and numeric helpers.
- `parseFloat` / `Number.parseFloat` / batch aliases.
- `Number.isNaN` / `Number.isFinite` batch aliases.
- RegExp test dispatch aliases.

Regression tests in `baseline_interpreter.rs` now exercise the high-risk alias
groups through mapped builtin IDs so future duplicate-arm regressions are caught
at the dispatch boundary, not only at helper level.

`tests/baseline_interpreter_conformance.rs` also compares the canonical
dispatch-arm inventory against the golden artifact at
`tests/golden_vectors/baseline_dispatch_arms.txt`. Any added duplicate changes
the total/unique/duplicate counts and fails the conformance test until the
runtime dispatch table and golden are reviewed together.

## Closure Criteria

`bd-1n5s6` is considered satisfied when the scan above remains at zero duplicate
runtime dispatch arms and the focused baseline gates complete or are blocked
only by unrelated pre-existing lib-test drift.
