#!/usr/bin/env bash
set -euo pipefail

# E.6 — FE-CLAIM-010 matrix-promotion gate (bd-cixqu.5.6)
#
# FE-CLAIM-010 is the ">= 3x weighted-geometric-mean throughput versus Node
# and Bun" claim. The matrix entry may only sit at `observed` when a FRESH,
# re-runnable Node/Bun denominator artifact actually demonstrates a live
# S_B >= 3.0 against BOTH baselines. This gate is the single fail-closed
# checkpoint that decides — and ENFORCES — that promotion:
#
#   * It reads the live PublicationGateDecision score artifact (the JSON
#     emitted by `frankenctl benchmark score` /
#     `benchmark_denominator::evaluate_publication_gate*`).
#   * It computes the promotion decision: PROMOTE_TO_OBSERVED iff a fresh
#     live score clears the threshold against BOTH baselines AND carries a
#     repro.lock; otherwise STAY_TARGET.
#   * It cross-checks the claim-to-proof matrix entry for FE-CLAIM-010 and
#     fails closed if the matrix OVER-CLAIMS (state == observed) without a
#     cleared, reproducible score. Under-claiming (matrix says target while
#     a cleared score exists) is surfaced as an advisory, not a failure —
#     honesty is the conservative direction.
#
# The honest outcome documented in bd-cixqu.5.6: "Only if the live S_B
# clears 3.0. If engineering doesn't deliver that number, the matrix stays
# TARGETED — that's the honest outcome and is preferable to fudging."
#
# This gate is pure bash + jq + awk so it is verifiable even while the Rust
# crate is mid-refactor and cannot link.
#
# Modes:
#   ci        Evaluate the live tree and emit a decision artifact (default).
#   verify    Validate an existing decision artifact's schema/bead identity.
#   selftest  Drive synthetic clears/parity/fudge fixtures through `ci` and
#             assert the decision + fail-closed behaviour in each case.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"

bead_id="bd-cixqu.5.6"
claim_id="FE-CLAIM-010"
component="fe_claim_010_promotion_gate"
schema_version="franken-engine.fe-claim-010-promotion-gate.v1"

matrix_path="${CLAIM_TO_PROOF_MATRIX_PATH:-docs/claim_to_proof_matrix_v1.json}"
weights_path="${FE_CLAIM_010_WEIGHTS_PATH:-docs/benchmark_denominator_weights_v1.json}"
score_path="${FE_CLAIM_010_SCORE_PATH:-}"
score_search_root="${FE_CLAIM_010_SCORE_SEARCH_ROOT:-artifacts/benchmark_denominator}"
artifact_root="${FE_CLAIM_010_PROMOTION_ARTIFACT_ROOT:-artifacts/fe_claim_010_promotion}"

# Stable error codes routed on by downstream structured-event consumers.
ERR_OVERCLAIM="FeClaim010PromotionError::ObservedWithoutClearedThreshold"
ERR_MISSING_REPRO="FeClaim010PromotionError::ObservedWithoutReproLock"
ERR_MATRIX_SHAPE="FeClaim010PromotionError::MatrixEntryMissing"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the FE-CLAIM-010 promotion gate" >&2
  exit 2
fi

# float_ge A B  -> exit 0 iff A >= B (decimal compare, no bc dependency)
float_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'
}

# ── verify mode ───────────────────────────────────────────────────────────
if [[ "$mode" == "verify" ]]; then
  verify_path="${2:-}"
  if [[ -z "$verify_path" || ! -f "$verify_path" ]]; then
    echo "Error: verify mode needs an existing decision artifact path" >&2
    exit 1
  fi
  if ! jq empty <"$verify_path" 2>/dev/null; then
    echo "Error: invalid JSON in artifact: $verify_path" >&2
    exit 1
  fi
  got_schema="$(jq -r '.schema_version // empty' <"$verify_path")"
  got_bead="$(jq -r '.bead_id // empty' <"$verify_path")"
  got_claim="$(jq -r '.claim_id // empty' <"$verify_path")"
  if [[ "$got_schema" != "$schema_version" ]]; then
    echo "Error: schema mismatch. expected $schema_version got $got_schema" >&2
    exit 1
  fi
  if [[ "$got_bead" != "$bead_id" || "$got_claim" != "$claim_id" ]]; then
    echo "Error: identity mismatch. expected $bead_id/$claim_id got $got_bead/$got_claim" >&2
    exit 1
  fi
  echo "✓ FE-CLAIM-010 promotion decision artifact verified: $verify_path"
  exit 0
fi

# ── selftest mode ───────────────────────────────────────────────────────────
if [[ "$mode" == "selftest" ]]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/fe-claim-010-selftest.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  failures=0

  matrix_with_state() {
    # $1 = state (target|observed)
    jq -n --arg state "$1" '{
      schema_version: "franken-engine.claim-to-proof-matrix.v1",
      claims: [ {
        claim_id: "FE-CLAIM-010",
        claim_scope: "performance",
        actual_wording_state: $state,
        allowed_state: $state
      } ]
    }'
  }
  score_artifact() {
    # $1 dir  $2 vs_node  $3 vs_bun  $4 publish_allowed  $5 with_repro(0/1)
    mkdir -p "$1"
    jq -n --argjson n "$2" --argjson b "$3" --argjson p "$4" '{
      score_vs_node: $n, score_vs_bun: $b, publish_allowed: $p,
      blockers: [], native_coverage_progression: [], replacement_lineage_ids: [], events: []
    }' >"$1/publication_gate_decision.json"
    if [[ "$5" == "1" ]]; then printf '{"lock":"v1"}\n' >"$1/repro.lock"; fi
  }

  run_case() {
    # $1 label  $2 matrix_state  $3 vs_node  $4 vs_bun  $5 publish  $6 repro
    # $7 expect_decision  $8 expect_exit
    local label="$1" mstate="$2" vn="$3" vb="$4" pub="$5" repro="$6"
    local exp_dec="$7" exp_exit="$8"
    local cdir; cdir="$(mktemp -d "${work}/case.XXXXXX")"
    matrix_with_state "$mstate" >"${cdir}/matrix.json"
    score_artifact "${cdir}/score" "$vn" "$vb" "$pub" "$repro"
    local out exit_code
    set +e
    out="$(CLAIM_TO_PROOF_MATRIX_PATH="${cdir}/matrix.json" \
           FE_CLAIM_010_SCORE_PATH="${cdir}/score/publication_gate_decision.json" \
           FE_CLAIM_010_PROMOTION_ARTIFACT_ROOT="${cdir}/out" \
           "$0" ci 2>&1)"
    exit_code=$?
    set -e
    local report; report="$(printf '%s\n' "$out" | grep -oE 'fe_claim_010_promotion_gate_report=.*' | tail -1 | cut -d= -f2-)"
    local got_dec=""
    [[ -n "$report" && -f "$report" ]] && got_dec="$(jq -r '.decision' "$report")"
    if [[ "$exit_code" != "$exp_exit" ]]; then
      echo "FAIL selftest [$label]: expected exit $exp_exit got $exit_code" >&2
      failures=$((failures + 1))
    elif [[ "$got_dec" != "$exp_dec" ]]; then
      echo "FAIL selftest [$label]: expected decision $exp_dec got '$got_dec'" >&2
      failures=$((failures + 1))
    else
      echo "PASS selftest [$label]: decision=$got_dec exit=$exit_code"
    fi
  }

  # A: live score clears 3.0 on both baselines, has repro.lock, matrix already
  #    observed -> PROMOTE_TO_OBSERVED, consistent, exit 0.
  run_case "clears-and-observed" observed 3.2 3.5 true 1 PROMOTE_TO_OBSERVED 0
  # B: parity (~1.0x), matrix honestly target -> STAY_TARGET, consistent, exit 0.
  run_case "parity-and-target" target 1.06 1.08 false 0 STAY_TARGET 0
  # C: FUDGE — parity score but matrix says observed -> STAY_TARGET decision,
  #    matrix over-claims -> fail closed, exit 1.
  run_case "parity-but-observed-fudge" observed 1.06 1.08 false 0 STAY_TARGET 1
  # D: clears threshold but NO repro.lock while matrix observed -> fail closed.
  run_case "clears-no-reprolock-observed" observed 3.2 3.5 true 0 STAY_TARGET 1

  if [[ "$failures" -ne 0 ]]; then
    echo "FE-CLAIM-010 promotion gate selftest: ${failures} failure(s)" >&2
    exit 1
  fi
  echo "FE-CLAIM-010 promotion gate selftest: all cases passed"
  exit 0
fi

if [[ "$mode" != "ci" ]]; then
  echo "Usage: $0 [ci|verify <artifact>|selftest]" >&2
  exit 64
fi

# ── ci mode: evaluate the live tree ─────────────────────────────────────────
if [[ ! -f "$matrix_path" ]]; then
  echo "missing claim matrix: $matrix_path" >&2
  exit 1
fi

# Threshold + comparator come from the typed weight contract (E.4); default to
# the normative >= 3.0 if the contract is absent.
threshold="3.0"
comparator=">="
if [[ -f "$weights_path" ]]; then
  t="$(jq -r '.gate.threshold // empty' "$weights_path" 2>/dev/null || true)"
  c="$(jq -r '.gate.comparator // empty' "$weights_path" 2>/dev/null || true)"
  [[ -n "$t" && "$t" != "null" ]] && threshold="$t"
  [[ -n "$c" && "$c" != "null" ]] && comparator="$c"
fi

# Locate the FE-CLAIM-010 matrix entry.
claim_json="$(jq -c --arg id "$claim_id" '.claims[]? | select(.claim_id == $id)' "$matrix_path")"
if [[ -z "$claim_json" ]]; then
  echo "${ERR_MATRIX_SHAPE}: no $claim_id entry in $matrix_path" >&2
  exit 1
fi
matrix_state="$(jq -r '.actual_wording_state // ""' <<<"$claim_json")"
matrix_allowed="$(jq -r '.allowed_state // ""' <<<"$claim_json")"

# Discover the live PublicationGateDecision score artifact.
if [[ -z "$score_path" && -d "$score_search_root" ]]; then
  while IFS= read -r cand; do
    if jq -e 'has("score_vs_node") and has("score_vs_bun")' "$cand" >/dev/null 2>&1; then
      score_path="$cand"
      break
    fi
  done < <(find "$score_search_root" -type f -name '*.json' -printf '%T@ %p\n' 2>/dev/null \
             | sort -nr | cut -d' ' -f2-)
fi

has_live_score="false"
score_vs_node="null"
score_vs_bun="null"
publish_allowed="false"
has_repro_lock="false"
meets_threshold="false"

if [[ -n "$score_path" && -f "$score_path" ]] \
    && jq -e 'has("score_vs_node") and has("score_vs_bun")' "$score_path" >/dev/null 2>&1; then
  has_live_score="true"
  score_vs_node="$(jq -r '.score_vs_node' "$score_path")"
  score_vs_bun="$(jq -r '.score_vs_bun' "$score_path")"
  publish_allowed="$(jq -r '.publish_allowed // false' "$score_path")"
  score_dir="$(dirname "$score_path")"
  if [[ -f "${score_dir}/repro.lock" ]] \
      || find "$score_dir" -maxdepth 3 -name repro.lock -type f -print -quit 2>/dev/null | grep -q .; then
    has_repro_lock="true"
  fi
  if float_ge "$score_vs_node" "$threshold" && float_ge "$score_vs_bun" "$threshold"; then
    meets_threshold="true"
  fi
fi

# Promotion decision.
decision="STAY_TARGET"
decision_reason="No fresh Node/Bun denominator artifact demonstrates S_B ${comparator} ${threshold} against both baselines; FE-CLAIM-010 honestly remains target."
if [[ "$has_live_score" == "true" && "$meets_threshold" == "true" \
      && "$publish_allowed" == "true" && "$has_repro_lock" == "true" ]]; then
  decision="PROMOTE_TO_OBSERVED"
  decision_reason="Live S_B clears ${threshold} on both baselines (node=${score_vs_node}, bun=${score_vs_bun}) with a reproducible, publish-allowed artifact; promotion to observed is warranted."
fi

# Fail-closed consistency check against the matrix.
consistent="true"
consistency_error=""
status="pass"
exit_code=0
if [[ "$decision" == "STAY_TARGET" && "$matrix_state" == "observed" ]]; then
  consistent="false"
  consistency_error="$ERR_OVERCLAIM"
  status="fail"
  exit_code=1
elif [[ "$decision" == "PROMOTE_TO_OBSERVED" ]]; then
  if [[ "$has_repro_lock" != "true" ]]; then
    consistent="false"
    consistency_error="$ERR_MISSING_REPRO"
    status="fail"
    exit_code=1
  elif [[ "$matrix_state" != "observed" ]]; then
    # Under-claim: cleared score exists but matrix still target. Honest /
    # conservative; advise promotion but do not fail the gate.
    consistency_error="advisory: cleared score present; promote $claim_id to observed"
  fi
fi

# Emit the decision artifact.
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
mkdir -p "$run_dir"
report_path="${run_dir}/promotion_decision.json"
commands_path="${run_dir}/commands.txt"
printf './scripts/run_fe_claim_010_promotion_gate.sh %s\n' "$mode" >"$commands_path"

jq -n \
  --arg schema "$schema_version" \
  --arg bead "$bead_id" \
  --arg claim "$claim_id" \
  --arg component "$component" \
  --arg threshold "$threshold" \
  --arg comparator "$comparator" \
  --arg matrix_path "$matrix_path" \
  --arg matrix_state "$matrix_state" \
  --arg matrix_allowed "$matrix_allowed" \
  --arg score_path "${score_path:-}" \
  --argjson has_live_score "$has_live_score" \
  --arg score_vs_node "$score_vs_node" \
  --arg score_vs_bun "$score_vs_bun" \
  --argjson publish_allowed "$publish_allowed" \
  --argjson has_repro_lock "$has_repro_lock" \
  --argjson meets_threshold "$meets_threshold" \
  --arg decision "$decision" \
  --arg decision_reason "$decision_reason" \
  --argjson consistent "$consistent" \
  --arg consistency_error "$consistency_error" \
  --arg status "$status" \
  --arg generated_utc "$timestamp" \
  '{
    schema_version: $schema,
    bead_id: $bead,
    claim_id: $claim,
    component: $component,
    generated_utc: $generated_utc,
    threshold: ($threshold | tonumber),
    comparator: $comparator,
    matrix: { path: $matrix_path, actual_wording_state: $matrix_state, allowed_state: $matrix_allowed },
    live_score: {
      present: $has_live_score,
      path: (if $score_path == "" then null else $score_path end),
      score_vs_node: (try ($score_vs_node | tonumber) catch null),
      score_vs_bun: (try ($score_vs_bun | tonumber) catch null),
      publish_allowed: $publish_allowed,
      has_repro_lock: $has_repro_lock,
      meets_threshold: $meets_threshold
    },
    decision: $decision,
    decision_reason: $decision_reason,
    consistent: $consistent,
    consistency_error: (if $consistency_error == "" then null else $consistency_error end),
    status: $status
  }' >"$report_path"

echo "fe_claim_010_promotion_gate_report=${report_path}"
echo "FE-CLAIM-010 promotion decision: ${decision} (matrix state: ${matrix_state}, status: ${status})"
echo "  ${decision_reason}"

if [[ "$exit_code" -ne 0 ]]; then
  echo "${consistency_error}: matrix over-claims FE-CLAIM-010 relative to live S_B evidence" >&2
  exit "$exit_code"
fi
if [[ -n "$consistency_error" ]]; then
  echo "${consistency_error}" >&2
fi
exit 0
