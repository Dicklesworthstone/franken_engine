# README Reality Check Gap Analysis

Date: 2026-04-21

Scope: README.md claims compared against the current repository state. Code, scripts, package metadata, and checked-in artifacts are treated as ground truth.

## Summary

The README describes a high-trust native runtime with shipped install paths, deterministic replay, cryptographic evidence, cross-platform binaries, and Node/Bun-relevant runtime posture. The codebase has real foundations for many of those areas, but several README claims currently read as delivered surfaces while the implementation is either missing, advisory-only, or explicitly mocked.

Top three tracking beads created:

- `bd-2iyoa`: README install surface points at missing artifacts
- `bd-1ub85`: Test262 conformance runner reports mock data
- `bd-2ox4b`: Cross-platform matrix gate is non-blocking by default

## Gap 1: Install And Release Surface Is Advertised But Missing

README claim:

- The Quick Install block points users at `https://raw.githubusercontent.com/Dicklesworthstone/franken_engine/main/install.sh`.
- The README says Linux, macOS, and Windows support is available with architecture-aware binaries.
- The cargo install path is documented as `cargo install frankenengine-cli`.

Actual state:

- There is no root `install.sh` in this repository.
- `cargo metadata --no-deps --format-version 1` reports these package names: `frankenengine-engine`, `frankenengine-extension-host`, `frankenengine-test-support`, and `frankenengine-metamorphic`.
- No package named `frankenengine-cli` is present in the current workspace metadata.

Impact:

This is the most direct user-facing mismatch. A new user following the first two install paths will hit missing or unpublished artifacts before reaching the actual runtime.

Tracking:

- `bd-2iyoa`

Recommended resolution:

Either provide and verify the advertised installer, cargo package, and release artifacts, or narrow README installation language to the build-from-source path that actually exists.

## Gap 2: Test262 Conformance Evidence Is Mocked

README claim:

- FrankenEngine is positioned as a native runtime substrate relevant to Node/Bun-style execution workloads.
- The README repeatedly ties significant runtime claims to reproducible evidence and no-placeholder artifact discipline.

Actual state:

- `crates/franken-engine/src/test262_conformance_runner.rs` says the MVP creates a mock report instead of discovering and executing real Test262 tests.
- The runner uses `mock-commit-hash`.
- Individual test execution simulates parser/lowering/orchestrator behavior instead of running the implementation path.
- Result distributions are deterministic mock percentages, not observed conformance outcomes.

Impact:

Any release, README, or operator claim that treats Test262 output as conformance evidence is currently claim-bearing mock data. This undermines the runtime compatibility posture more than a missing feature would, because the surface looks like evidence.

Tracking:

- `bd-1ub85`

Recommended resolution:

Replace mock generation with real fixture discovery and execution through the parser/lowering/orchestrator path, or explicitly label the current output as simulated and non-claim-bearing in all README/docs/gates.

## Gap 3: Cross-Platform Matrix Is Advisory Unless Strict Mode Is Enabled

README claim:

- The README advertises Linux, macOS, and Windows support with architecture-aware binaries.
- The cross-platform matrix section presents the gate as verification for the supported target matrix.

Actual state:

- `scripts/run_rgc_cross_platform_matrix_gate.sh` defaults `RGC_CROSS_PLATFORM_REQUIRE_MATRIX` to `0`.
- Missing required target manifests and critical deltas only become fatal when `strict_matrix` is true.
- `strict_matrix` is only enabled for `matrix` mode or when `RGC_CROSS_PLATFORM_REQUIRE_MATRIX=1`.

Impact:

The default `ci` path can produce matrix artifacts without making missing target evidence release-blocking. That is a weaker guarantee than the README support language implies.

Tracking:

- `bd-2ox4b`

Recommended resolution:

Make the advertised support matrix blocking in CI/release paths, or update the README to say default CI mode is advisory and strict matrix verification requires `matrix` mode or `RGC_CROSS_PLATFORM_REQUIRE_MATRIX=1`.

## Gap 4: React No-VDOM Surface Is A Placeholder Parser

README claim:

- `frankenctl react` is listed as a shipped operator surface.

Actual state:

- `crates/franken-engine/src/bin/franken_react_sidecar.rs` says React/JSX parsing is a placeholder.
- Component discovery is based on `source_code.contains("function ")` and `source_code.contains("return ")`.
- The generated component is a hard-coded `ExampleComponent` with a hard-coded `div` child.

Impact:

The sidecar can produce structured output, but it is not a real React or JSX parser. README language should not imply a production React transformation path unless the real parser/generator is wired.

Recommended resolution:

Either wire a real JSX/React parser path or mark the sidecar as an experimental placeholder in the README and command docs.

## Gap 5: Replay CLI Does Not Match The High-Severity Counterfactual Claim

README claim:

- Deterministic replay is described as bit-stable replay for high-severity decision paths with counterfactual policy simulation.
- Quick examples show `frankenctl replay run` as the replay entry point.

Actual state:

- `frankenctl replay run` loads a `NondeterminismTrace`, validates it, optionally compares another trace, replays event values, and reports divergence counts.
- The command path does not orchestrate high-severity decision replay or counterfactual policy simulation.

Impact:

The lower-level trace replay is useful, but the README wording implies a stronger decision-forensics workflow than the shown CLI actually provides.

Recommended resolution:

Either connect `frankenctl replay` to the decision/counterfactual replay engines, or make the README distinguish trace validation from high-severity decision replay.

