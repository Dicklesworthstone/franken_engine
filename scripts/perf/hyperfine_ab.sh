#!/usr/bin/env bash
set -euo pipefail

# PERF-INFRA.4 (bd-o4cbn.8.4) — Hyperfine A/B wall-clock harness.
#
# Runs two binaries (typically a frozen baseline vs the current build)
# under identical invocation args via hyperfine, exports the raw JSON, and
# renders a comparison.md with mean / std-dev / 95% CI for each binary plus
# the relative speedup.
#
# Usage:
#   scripts/perf/hyperfine_ab.sh [--runs N] [--warmup N] [--out DIR] \
#       <bin_a> <bin_b> [invocation_args...]
#
# Example:
#   scripts/perf/hyperfine_ab.sh \
#       artifacts/baselines/<sha-a>/frankenctl \
#       target/release/frankenctl \
#       run --input ./demo.js --extension-id demo --out /tmp/o.json
#
# Defaults: --warmup 3 --runs 20, out=tests/artifacts/perf/hyperfine/<ts>/
#
# Exit codes:
#   0  both binaries ran successfully; comparison emitted
#   1  hyperfine reported a command failure (a binary exited non-zero)
#   2  usage / environment error (missing binary, bad args, no hyperfine/jq)

usage() {
    cat >&2 <<'USAGE'
Usage: hyperfine_ab.sh [--runs N] [--warmup N] [--out DIR] <bin_a> <bin_b> [invocation_args...]

  --runs N       hyperfine --runs (default 20)
  --warmup N     hyperfine --warmup (default 3)
  --out DIR      output dir (default tests/artifacts/perf/hyperfine/<ts>/)
  <bin_a>        baseline binary (path or command)
  <bin_b>        candidate binary (path or command)
  [args...]      invocation args passed identically to BOTH binaries
  -h, --help     show this help
USAGE
}

RUNS=20
WARMUP=3
OUT=""

# Leading optional flags, then positional bin_a bin_b args...
while [ $# -gt 0 ]; do
    case "$1" in
        --runs)   RUNS="${2:-}"; shift 2 ;;
        --warmup) WARMUP="${2:-}"; shift 2 ;;
        --out)    OUT="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) echo "Error: unknown flag: $1" >&2; usage; exit 2 ;;
        *) break ;;
    esac
done

if [ $# -lt 2 ]; then
    echo "Error: need at least <bin_a> and <bin_b>" >&2
    usage
    exit 2
fi

BIN_A="$1"; shift
BIN_B="$1"; shift
# Remaining "$@" are the shared invocation args.

case "$RUNS" in   ''|*[!0-9]*) echo "Error: --runs must be a positive integer" >&2; exit 2 ;; esac
case "$WARMUP" in ''|*[!0-9]*) echo "Error: --warmup must be a non-negative integer" >&2; exit 2 ;; esac

if ! command -v hyperfine >/dev/null 2>&1; then
    echo "Error: hyperfine is required but not found on PATH" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required but not found on PATH" >&2
    exit 2
fi

# If a binary argument looks like a filesystem path, require it to exist and
# be executable. A bare command name (resolved via PATH) is left to hyperfine.
check_bin() {
    local b="$1" label="$2"
    case "$b" in
        */*)
            if [ ! -e "$b" ]; then
                echo "Error: $label binary not found: $b" >&2; exit 2
            fi
            if [ ! -x "$b" ]; then
                echo "Error: $label binary not executable: $b" >&2; exit 2
            fi
            ;;
    esac
}
check_bin "$BIN_A" "bin_a"
check_bin "$BIN_B" "bin_b"

if [ -z "$OUT" ]; then
    OUT="tests/artifacts/perf/hyperfine/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$OUT"

JSON="$OUT/a_vs_b.json"
REPORT="$OUT/comparison.md"

# Build shell-quoted command strings so invocation args survive intact.
CMD_A="$(printf '%q ' "$BIN_A" "$@")"
CMD_B="$(printf '%q ' "$BIN_B" "$@")"
NAME_A="A:$(basename -- "$BIN_A")"
NAME_B="B:$(basename -- "$BIN_B")"

echo "Running hyperfine: warmup=$WARMUP runs=$RUNS"
echo "  A = $CMD_A"
echo "  B = $CMD_B"

# hyperfine fails closed (non-zero) if either command exits non-zero; we do
# NOT pass --ignore-failure, so a broken binary surfaces as a gate failure.
set +e
hyperfine \
    --warmup "$WARMUP" \
    --runs "$RUNS" \
    --command-name "$NAME_A" \
    --command-name "$NAME_B" \
    --export-json "$JSON" \
    "$CMD_A" "$CMD_B"
hf_status=$?
set -e

if [ "$hf_status" -ne 0 ] || [ ! -f "$JSON" ]; then
    echo "Error: hyperfine run failed (status $hf_status) — at least one binary did not succeed" >&2
    exit 1
fi

# Render comparison.md. 95% CI uses the normal approximation
# mean ± 1.96 * stddev / sqrt(runs).
jq -r --arg runs "$RUNS" --arg warmup "$WARMUP" --arg na "$NAME_A" --arg nb "$NAME_B" '
  def ms(s): (s * 1000.0);
  def round2: (. * 100.0 | floor) / 100.0;
  def ci_low(mean; sd; n): (mean - 1.96 * sd / (n | sqrt));
  def ci_high(mean; sd; n): (mean + 1.96 * sd / (n | sqrt));
  ($runs | tonumber) as $n
  | .results as $r
  | ($r[0].mean) as $ma | ($r[1].mean) as $mb
  | (if $ma <= $mb then $mb / $ma else $ma / $mb end) as $speedup
  | (if $ma <= $mb then $na else $nb end) as $faster
  | "# Hyperfine A/B comparison\n"
  + "\n- Runs: \($runs) (warmup \($warmup)), 95% CI via normal approx (mean ± 1.96·sd/√n)\n"
  + "\n| Binary | Mean (ms) | Std-dev (ms) | Median (ms) | CI95 low (ms) | CI95 high (ms) |\n"
  + "|---|---:|---:|---:|---:|---:|\n"
  + ( [ $r[] |
      "| \(.command) | \(ms(.mean) | round2) | \(ms(.stddev) | round2) | \(ms(.median) | round2) | \(ms(ci_low(.mean; .stddev; $n)) | round2) | \(ms(ci_high(.mean; .stddev; $n)) | round2) |"
    ] | join("\n") )
  + "\n\n## Relative speedup\n"
  + "\n- Faster: **\($faster)**\n"
  + "- Speedup (slower_mean / faster_mean): **\($speedup | . * 100.0 | floor | . / 100.0)×**\n"
' "$JSON" > "$REPORT"

echo "Wrote $JSON and $REPORT"
cat "$REPORT"
exit 0
