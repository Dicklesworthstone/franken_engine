#!/usr/bin/env bash
set -euo pipefail

# PERF-INFRA.2 (bd-o4cbn.8.2) — Performance regression gate.
#
# Diffs the current Criterion benchmark run against a frozen baseline
# (see scripts/perf/freeze_baseline.sh) for each hot_paths sub-bench and
# fails closed (non-zero exit) when any sub-bench regresses past the
# configured threshold.
#
# Usage:
#   scripts/perf/regression_gate.sh \
#       --baseline tests/artifacts/perf/baselines/<git-sha>/ \
#       --current  target/criterion/real_runtime_hot_paths/ \
#       --threshold-pct 5 \
#       --out tests/artifacts/perf/regressions/<ts>/
#
# Outputs (under --out):
#   regressions.jsonl     one perf.regression.diff event per sub-bench
#   regression_report.md  human-readable summary table
#
# Exit codes:
#   0  no sub-bench regressed past the threshold
#   1  at least one sub-bench regressed
#   2  usage / environment error (missing baseline dir, bad args, no jq)

usage() {
    cat >&2 <<'USAGE'
Usage: regression_gate.sh --baseline <dir> [--current <dir>] [--threshold-pct <n>] [--out <dir>]

  --baseline <dir>      Frozen baseline dir (tests/artifacts/perf/baselines/<git-sha>/). REQUIRED.
  --current  <dir>      Current Criterion dir. Default: target/criterion/real_runtime_hot_paths/
  --threshold-pct <n>   Regression threshold in percent (float ok). Default: 5
  --out <dir>           Output dir. Default: tests/artifacts/perf/regressions/<ts>/
  -h, --help            Show this help.
USAGE
}

# --- argument parsing -------------------------------------------------------
BASELINE=""
CURRENT="target/criterion/real_runtime_hot_paths"
THRESHOLD_PCT="5"
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --baseline)      BASELINE="${2:-}"; shift 2 ;;
        --current)       CURRENT="${2:-}"; shift 2 ;;
        --threshold-pct) THRESHOLD_PCT="${2:-}"; shift 2 ;;
        --out)           OUT="${2:-}"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "Error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if [ -z "$BASELINE" ]; then
    echo "Error: --baseline is required" >&2
    usage
    exit 2
fi
if [ ! -d "$BASELINE" ]; then
    echo "Error: baseline directory not found: $BASELINE" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required but not found on PATH" >&2
    exit 2
fi
# Validate the threshold is numeric.
if ! awk -v t="$THRESHOLD_PCT" 'BEGIN { if (t+0 != t && t != 0) exit 1; exit 0 }' </dev/null 2>/dev/null; then
    : # awk numeric coercion is permissive; do an explicit regex check below.
fi
case "$THRESHOLD_PCT" in
    ''|*[!0-9.]*) echo "Error: --threshold-pct must be numeric: $THRESHOLD_PCT" >&2; exit 2 ;;
esac

if [ -z "$OUT" ]; then
    OUT="tests/artifacts/perf/regressions/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUT"

JSONL="$OUT/regressions.jsonl"
REPORT="$OUT/regression_report.md"
: > "$JSONL"

# The eight hot_paths sub-benches (keep in sync with benches/hot_paths.rs
# and scripts/perf/freeze_baseline.sh).
BENCH_FUNCTIONS=(
    "parser_arena_materialization"
    "lowering_pipeline_ir3"
    "baseline_interpreter_eval"
    "baseline_value_string_clone"
    "iterator_protocol_trace"
    "scheduler_queue_commit"
    "evidence_ledger_bundle"
    "transport_certificate_serialization"
)

# Resolve a baseline estimates file, accepting both naming conventions:
#   criterion_<fn>_estimates.json  (freeze_baseline.sh output)
#   <fn>_estimates.json            (bead spec shorthand)
baseline_file() {
    local fn="$1"
    local a="$BASELINE/criterion_${fn}_estimates.json"
    local b="$BASELINE/${fn}_estimates.json"
    if   [ -f "$a" ]; then printf '%s' "$a"
    elif [ -f "$b" ]; then printf '%s' "$b"
    else printf ''
    fi
}

# Resolve the current estimates file. Criterion writes the freshest run under
# <fn>/new/estimates.json; fall back to <fn>/base/estimates.json.
current_file() {
    local fn="$1"
    local a="$CURRENT/${fn}/new/estimates.json"
    local b="$CURRENT/${fn}/base/estimates.json"
    if   [ -f "$a" ]; then printf '%s' "$a"
    elif [ -f "$b" ]; then printf '%s' "$b"
    else printf ''
    fi
}

point_estimate() {
    # Extracts .mean.point_estimate; prints empty on any failure.
    jq -er '.mean.point_estimate' "$1" 2>/dev/null || printf ''
}

now_rfc3339() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# --- per-sub-bench diff -----------------------------------------------------
had_regression=0
n_pass=0
n_regression=0
n_missing=0

# Markdown table accumulates as we go.
{
    echo "# Performance regression report"
    echo
    echo "- Generated: $(now_rfc3339)"
    echo "- Baseline: \`$BASELINE\`"
    echo "- Current: \`$CURRENT\`"
    echo "- Threshold: ${THRESHOLD_PCT}% (regression when delta_pct > threshold)"
    echo
    echo "| Sub-bench | Baseline (ns) | Current (ns) | Δ% | Verdict |"
    echo "|---|---:|---:|---:|---|"
} > "$REPORT"

for fn in "${BENCH_FUNCTIONS[@]}"; do
    bfile="$(baseline_file "$fn")"
    cfile="$(current_file "$fn")"
    ts="$(now_rfc3339)"

    if [ -z "$bfile" ] || [ -z "$cfile" ]; then
        n_missing=$((n_missing + 1))
        reason="missing"
        [ -z "$bfile" ] && reason="missing-baseline"
        [ -z "$cfile" ] && reason="missing-current"
        [ -z "$bfile" ] && [ -z "$cfile" ] && reason="missing-both"
        printf '{"ts":"%s","event":"perf.regression.diff","sub_bench":"%s","baseline_ns":null,"current_ns":null,"delta_pct":null,"threshold_pct":%s,"verdict":"%s"}\n' \
            "$ts" "$fn" "$THRESHOLD_PCT" "$reason" >> "$JSONL"
        echo "| $fn | — | — | — | $reason |" >> "$REPORT"
        echo "[SKIP] $fn: $reason" >&2
        continue
    fi

    base_ns="$(point_estimate "$bfile")"
    cur_ns="$(point_estimate "$cfile")"

    if [ -z "$base_ns" ] || [ -z "$cur_ns" ]; then
        n_missing=$((n_missing + 1))
        printf '{"ts":"%s","event":"perf.regression.diff","sub_bench":"%s","baseline_ns":null,"current_ns":null,"delta_pct":null,"threshold_pct":%s,"verdict":"unparsable"}\n' \
            "$ts" "$fn" "$THRESHOLD_PCT" >> "$JSONL"
        echo "| $fn | — | — | — | unparsable |" >> "$REPORT"
        echo "[SKIP] $fn: could not parse .mean.point_estimate" >&2
        continue
    fi

    # delta_pct = (current - baseline) / baseline * 100; verdict via awk.
    read -r delta_pct verdict base_int cur_int <<EOF
$(awk -v b="$base_ns" -v c="$cur_ns" -v t="$THRESHOLD_PCT" 'BEGIN {
    if (b <= 0) { printf "0 baseline_nonpositive %d %d\n", (b+0.5), (c+0.5); exit }
    d = (c - b) / b * 100.0;
    v = (d > t) ? "regression" : "pass";
    printf "%.4f %s %d %d\n", d, v, (b+0.5), (c+0.5);
}')
EOF

    printf '{"ts":"%s","event":"perf.regression.diff","sub_bench":"%s","baseline_ns":%s,"current_ns":%s,"delta_pct":%s,"threshold_pct":%s,"verdict":"%s"}\n' \
        "$ts" "$fn" "$base_int" "$cur_int" "$delta_pct" "$THRESHOLD_PCT" "$verdict" >> "$JSONL"
    echo "| $fn | $base_int | $cur_int | ${delta_pct} | $verdict |" >> "$REPORT"

    if [ "$verdict" = "regression" ]; then
        had_regression=1
        n_regression=$((n_regression + 1))
        echo "[REGRESSION] $fn: ${delta_pct}% > ${THRESHOLD_PCT}% (baseline ${base_int}ns -> current ${cur_int}ns)" >&2
    elif [ "$verdict" = "baseline_nonpositive" ]; then
        n_missing=$((n_missing + 1))
        echo "[SKIP] $fn: non-positive baseline" >&2
    else
        n_pass=$((n_pass + 1))
        echo "[OK] $fn: ${delta_pct}% (baseline ${base_int}ns -> current ${cur_int}ns)"
    fi
done

{
    echo
    echo "## Summary"
    echo
    echo "- pass: $n_pass"
    echo "- regression: $n_regression"
    echo "- missing/unparsable: $n_missing"
    echo
    if [ "$had_regression" -ne 0 ]; then
        echo "**VERDICT: REGRESSION** — at least one sub-bench exceeded the ${THRESHOLD_PCT}% threshold."
    else
        echo "**VERDICT: PASS** — no sub-bench exceeded the ${THRESHOLD_PCT}% threshold."
    fi
} >> "$REPORT"

echo "Wrote $JSONL and $REPORT"

if [ "$had_regression" -ne 0 ]; then
    echo "perf regression gate: FAIL ($n_regression regression(s))" >&2
    exit 1
fi
echo "perf regression gate: PASS"
exit 0
