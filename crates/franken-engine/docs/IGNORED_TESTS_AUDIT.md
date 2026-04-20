# Ignored Tests Audit

Date: 2026-04-20
Reviewer: VioletSwan
Scope: `crates/franken-engine/tests/*.rs`
Command: `grep -n '#\[ignore\]\|#\[cfg(feature' crates/franken-engine/tests/*.rs`

## Summary

The integration test scan found one ignored test and two positive feature gates. No broad file-level skip was found outside the explicit `asupersync-integration` contract split. The ignored test is a fixture maintenance utility, not assertion coverage.

## Findings

| File | Line | Gate | Entry | Justification | Risk | Recommendation |
| --- | ---: | --- | --- | --- | --- | --- |
| `crates/franken-engine/tests/dependency_contracts.rs` | 6 | `#[cfg(feature = "asupersync-integration")]` | `mod asupersync_contracts` | Valid build-mode split. The crate default features include `asupersync-integration`, so this module runs under default cargo invocations and verifies external asupersync dependency contract compilation. | Low | Keep. If no-default-feature CI is required, ensure it also runs this file to exercise `standalone_contracts`. |
| `crates/franken-engine/tests/dependency_contracts.rs` | 89 | `#[cfg(feature = "asupersync-integration")]` | Branch inside `build_mode_verification` | Valid compile-time reporting branch paired with the `not(feature = "asupersync-integration")` branch below it. It documents which dependency mode compiled. | Low | Keep. This is mode introspection, not skipped behavioral coverage. |
| `crates/franken-engine/tests/parser_phase0_semantic_fixtures.rs` | 100 | `#[ignore]` | `print_parser_phase0_fixture_hashes` | Justified as a manual fixture maintenance helper. It prints canonical hashes for `tests/fixtures/parser_phase0_semantic_fixtures.json`; active assertion coverage is provided by `parser_phase0_semantic_fixtures_match_expected_hashes` and follow-on fixture catalog invariant tests in the same file. | Low | Keep ignored, but retain it as a utility only. If it becomes normative, convert output to checked golden assertions instead of relying on manual invocation. |

## Active Coverage Check

- `parser_phase0_semantic_fixtures_match_expected_hashes` actively parses every parser phase0 fixture and asserts canonical hash stability.
- Fixture catalog invariant tests assert non-empty fixture sets, script/module coverage, unique IDs, non-empty family IDs, stable schema version, hash prefixes, non-empty sources, and valid parse goals.
- `dependency_contracts.rs` has positive coverage for both feature-enabled and standalone compile modes, selected by cargo feature configuration.

## Conclusion

No unjustified ignored integration test was found. The only `#[ignore]` entry is a print-only maintenance helper with active assertion coverage nearby. The `asupersync-integration` feature gates are expected because `crates/franken-engine/Cargo.toml` enables that feature by default while preserving standalone-mode compilation checks.
