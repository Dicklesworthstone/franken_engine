#!/usr/bin/env bash
#
# CEI D.2 (bd-sde5e.4.2) — real tc39/test262 corpus pass-rate measurement.
#
# Runs `franken_test262_runner --suite-path <checkout>` against a *real, pinned*
# tc39/test262 checkout (not the 6-case curated smoke), producing a real
# denominator + pass-rate over a deterministic prefix of the ES2020-normative
# profile, and writes the committed measurement artifact
# `docs/test262_real_corpus_pass_rate_v1.json`.
#
# This is the honest counterpart to the curated, provisional
# `docs/test262_compatibility_pass_rate_v1.json` (denominator = 3): the curated
# posture stays the gated wording authority (full_suite_claim_allowed = false),
# while this artifact records what the engine actually does on a real
# thousands-case slice of the official suite. The measured pass-rate is expected
# to be low — the runtime ships a bounded JS surface and this harness's pass
# criterion does not preload Test262 harness includes — and that is the point:
# the number is real, not the fabricated high-water-mark it replaces.
#
# Fail-closed: if the pinned checkout is absent or at the wrong commit, the gate
# refuses (exit 2) rather than synthesizing numbers.
#
# Usage:
#   scripts/run_test262_real_corpus_pass_rate.sh [suite_path]
#
# Environment:
#   TEST262_SUITE_PATH     real tc39/test262 checkout (default: arg1 or
#                          /data/projects/test262_corpus)
#   TEST262_SAMPLE_COUNT   deterministic case cap (default: 2000)
#   TEST262_RUNNER_BIN     runner binary (default: target/release/franken_test262_runner)
#   TEST262_WORKER_COUNT   runner worker threads (default: 8)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Default: run the WHOLE ES2020-normative profile (tens of thousands of cases —
# the deterministic path-sorted prefix that `--sample-count` would take is all
# `built-ins/*`, which is unrepresentative). Set TEST262_SAMPLE_COUNT to cap it.
SUITE_PATH="${TEST262_SUITE_PATH:-${1:-/data/projects/test262_corpus}}"
SAMPLE_COUNT="${TEST262_SAMPLE_COUNT:-}"
RUNNER_BIN="${TEST262_RUNNER_BIN:-$PROJECT_ROOT/target/release/franken_test262_runner}"
WORKER_COUNT="${TEST262_WORKER_COUNT:-8}"
PINS="$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_pins.toml"
PROFILE="$PROJECT_ROOT/crates/franken-engine/tests/test262_es2020_profile.toml"
WAIVERS="$PROJECT_ROOT/crates/franken-engine/tests/test262_conformance_waivers.toml"
OUT_ARTIFACT="$PROJECT_ROOT/docs/test262_real_corpus_pass_rate_v1.json"
RUN_ROOT="$PROJECT_ROOT/artifacts/test262_real_corpus/$(date -u +%Y%m%dT%H%M%SZ)"

log() { printf '[t262-real] %s\n' "$*"; }
refuse() { printf '[t262-real] ERROR: %s\n' "$*" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || refuse "python3 required"
[[ -x "$RUNNER_BIN" ]] || refuse "runner binary not found/executable: $RUNNER_BIN (build: cargo build --release -p frankenengine-engine --bin franken_test262_runner)"
[[ -d "$SUITE_PATH/test" ]] || refuse "no tc39/test262 checkout at $SUITE_PATH (expected a 'test/' directory)"

# Verify the checkout is at the pinned commit (the same the harness enforces).
PINNED_COMMIT="$(python3 -c "import re,sys; print(next((re.search(r'\"?([0-9a-f]{40})\"?', l).group(1) for l in open('$PINS') if l.strip().startswith('test262_commit')), ''))" 2>/dev/null || true)"
ACTUAL_COMMIT="$(git -C "$SUITE_PATH" rev-parse HEAD 2>/dev/null || echo "")"
if [[ -n "$PINNED_COMMIT" && "$ACTUAL_COMMIT" != "$PINNED_COMMIT" ]]; then
    refuse "checkout at $SUITE_PATH is $ACTUAL_COMMIT, expected pinned $PINNED_COMMIT (run: git -C $SUITE_PATH fetch --depth 1 origin $PINNED_COMMIT && git -C $SUITE_PATH checkout $PINNED_COMMIT)"
fi

mkdir -p "$RUN_ROOT"
RUN_LOG="$RUN_ROOT/runner.log"
RUN_DATE="$(date -u +%Y-%m-%d)"

runner_args=(
    --pins "$PINS"
    --profile "$PROFILE"
    --waivers "$WAIVERS"
    --suite-path "$SUITE_PATH"
    --output-root "$RUN_ROOT"
    --run-date "$RUN_DATE"
    --worker-count "$WORKER_COUNT"
)
if [[ -n "$SAMPLE_COUNT" ]]; then
    runner_args+=(--sample-count "$SAMPLE_COUNT")
    log "running franken_test262_runner over real corpus (suite=$SUITE_PATH, sample=$SAMPLE_COUNT)"
else
    log "running franken_test262_runner over the FULL es2020-normative profile (suite=$SUITE_PATH)"
fi
# The runner exits non-zero when the release gate is "blocked" (any unwaived
# failure), which is expected on a real low-pass-rate slice; the per-case results
# and summary are still emitted, so we capture the log and parse the summary
# regardless of the exit code.
set +e
"$RUNNER_BIN" "${runner_args[@]}" >"$RUN_LOG" 2>&1
runner_rc=$?
set -e
log "runner exit=$runner_rc (non-zero is expected when the release gate blocks on real failures)"

# Parse the runner's `test262 <key>=<value>` summary lines.
get() { grep -E "^test262 $1=" "$RUN_LOG" | tail -1 | sed "s/^test262 $1=//"; }
TOTAL="$(get total_profile_tests)"
PASSED="$(get passed)"
FAILED="$(get failed)"
WAIVED="$(get waived)"
TIMED_OUT="$(get timed_out)"
CRASHED="$(get crashed)"
RUN_MANIFEST="$(get run_manifest)"

if [[ -z "$TOTAL" || -z "$PASSED" ]]; then
    log "runner log tail:"; tail -20 "$RUN_LOG" >&2
    refuse "runner did not emit a parseable summary (no total_profile_tests/passed) — refusing to synthesize"
fi
[[ "$TOTAL" -gt 0 ]] || refuse "real corpus yielded 0 cases — the harness path/profile is misconfigured"

log "real corpus: total=$TOTAL passed=$PASSED failed=$FAILED waived=$WAIVED timed_out=$TIMED_OUT crashed=$CRASHED"

GENERATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOTAL="$TOTAL" PASSED="$PASSED" FAILED="$FAILED" WAIVED="$WAIVED" \
TIMED_OUT="$TIMED_OUT" CRASHED="$CRASHED" GENERATED_UTC="$GENERATED_UTC" \
PINNED_COMMIT="$PINNED_COMMIT" SAMPLE_COUNT="$SAMPLE_COUNT" \
RUN_MANIFEST="$RUN_MANIFEST" OUT_ARTIFACT="$OUT_ARTIFACT" \
python3 <<'PY'
import json, os
total = int(os.environ["TOTAL"]); passed = int(os.environ["PASSED"])
failed = int(os.environ.get("FAILED") or 0); waived = int(os.environ.get("WAIVED") or 0)
timed_out = int(os.environ.get("TIMED_OUT") or 0); crashed = int(os.environ.get("CRASHED") or 0)
pass_rate_millionths = (passed * 1_000_000) // total if total else 0
body = {
    "schema_version": "franken-engine.test262-real-corpus-pass-rate.v1",
    "generated_at_utc": os.environ["GENERATED_UTC"],
    "component": "franken_test262_runner --suite-path",
    "owning_bead": "bd-sde5e.4.2",
    "proof_state": "real_corpus_measured",
    "claim_scope": "real_tc39_test262_es2020_normative",
    "test262_source_repo": "tc39/test262",
    "test262_commit": os.environ.get("PINNED_COMMIT", ""),
    "selected_profile": "es2020-normative",
    "sampling": (
        "deterministic path-sorted prefix of " + os.environ["SAMPLE_COUNT"] + " cases"
        if os.environ.get("SAMPLE_COUNT")
        else "full ES2020-normative profile (no sampling)"
    ),
    "sample_count_requested": (
        int(os.environ["SAMPLE_COUNT"]) if os.environ.get("SAMPLE_COUNT") else None
    ),
    "runner_command": (
        "franken_test262_runner --pins crates/franken-engine/tests/test262_conformance_pins.toml "
        "--profile crates/franken-engine/tests/test262_es2020_profile.toml "
        "--waivers crates/franken-engine/tests/test262_conformance_waivers.toml "
        "--suite-path <tc39/test262 checkout>"
        + (" --sample-count " + os.environ["SAMPLE_COUNT"] if os.environ.get("SAMPLE_COUNT") else "")
        + " --output-root <run-root>"
    ),
    "denominator": total,
    "passed": passed,
    "failed": failed,
    "skipped": 0,
    "waived": waived,
    "timed_out": timed_out,
    "crashed": crashed,
    "pass_rate_millionths": pass_rate_millionths,
    "full_suite_claim_allowed": False,
    "limitations": [
        (
            "deterministic path-sorted prefix of " + os.environ["SAMPLE_COUNT"]
            + " cases of the ES2020-normative profile"
            if os.environ.get("SAMPLE_COUNT")
            else "every case the ES2020-normative profile selects (language/* + built-ins/*); this profile is a subset of the full official corpus (it excludes annexB, ECMA-402, and post-ES2020 proposals)"
        ),
        "the harness pass criterion does not preload Test262 harness includes (assert.js, sta.js, propertyHelper.js), so positive tests that depend on them are counted as failures — the pass-rate is a conservative lower bound on conformance, not a spec-conformance score",
        "full official Test262 pass-rate claims require harness-include support",
        "profile excludes ECMA-402 and post-ES2020 proposal vectors",
    ],
}
with open(os.environ["OUT_ARTIFACT"], "w", encoding="utf-8") as fh:
    json.dump(body, fh, indent=2)
    fh.write("\n")
print(f"[t262-real] wrote {os.environ['OUT_ARTIFACT']} (denominator={total}, passed={passed}, "
      f"pass_rate={pass_rate_millionths/10000:.2f}%)")
PY

log "done. artifact: ${OUT_ARTIFACT#"$PROJECT_ROOT"/}  run bundle: ${RUN_ROOT#"$PROJECT_ROOT"/}"
