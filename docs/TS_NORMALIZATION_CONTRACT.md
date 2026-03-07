# TS Normalization Contract (bd-309)

This document defines the initial TypeScript-front-end normalization contract for FrankenEngine.

## Goal

Provide deterministic TS-to-ES2020-equivalent normalization before native IR execution, with witness artifacts that make transformation decisions auditable.

## Current Scope

Implemented in `crates/franken-engine/src/ts_normalization.rs`:
- type-only import elision
- simple enum lowering (`enum` -> `Object.freeze` object form)
- simple namespace lowering + merge (`namespace X { export const ... }`)
- simple legacy class-decorator lowering (`@decorator` + `class X {}`)
- constructor parameter-property lowering
- abstract class keyword lowering (`abstract class` -> `class`) via token-aware scanning outside strings/comments
- type annotation stripping
- definite-assignment assertion normalization via token-aware scanning outside strings/comments
- const-assertion normalization (`as const` stripping) via token-aware scanning outside strings/comments
- simple JSX lowering (`<X />`, `<X>expr</X>` -> `createElement`) when `jsx != preserve`
- capability intent extraction from `hostcall<"capability">` forms
- deterministic witness/event emission with stable governance keys
- compiler-option validation (`target=es2020`, `module in {esnext,commonjs}`, `jsx in {react-jsx,react,preserve}`)

Current explicit unsupported syntax (hard fail):
- namespace export forms beyond `export const|let|var <name> = <expr>`
- decorator targets that are not class declarations

## Witness + Logging

Normalization output includes:
- deterministic source hashes (`source_hash`, `normalized_hash`)
- deterministic compiler-option hash
- ordered normalization decisions
- extracted capability intents
- structured events with:
  - `trace_id`
  - `decision_id`
  - `policy_id`
  - `component`
  - `event`
  - `outcome`
  - `error_code`

## Test Coverage

Implemented tests cover:
- deterministic normalization repeatability
- type-only import elision
- enum lowering
- namespace merge lowering
- legacy class-decorator lowering
- parameter-property lowering
- abstract-class lowering
- compiler-option validation failures
- JSX preserve-mode behavior
- JSX lowering
- capability-intent extraction
- empty-input and unsupported-feature failure behavior
- governance field presence in witness/events

Integration test file:
- `crates/franken-engine/tests/ts_normalization.rs`

## Suite Runner

```bash
./scripts/run_ts_normalization_suite.sh check
./scripts/run_ts_normalization_suite.sh test
./scripts/run_ts_normalization_suite.sh ci
```

Artifacts:
- `artifacts/ts_normalization/<timestamp>/run_manifest.json`
- `artifacts/ts_normalization/<timestamp>/events.jsonl`
- `artifacts/ts_normalization/<timestamp>/commands.txt`

## Next Steps

- expand normalization support for richer namespace/decorator forms
- add behavior-equivalence lockstep checks against `tsc` output
- emit richer source-map provenance and replay pointers
