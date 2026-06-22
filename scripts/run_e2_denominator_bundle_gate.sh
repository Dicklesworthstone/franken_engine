#!/usr/bin/env bash
set -euo pipefail

# E2 Node/Bun denominator reproducibility-bundle gate (bd-fqlfw.2.6).
#
# Modes:
#   ci | verify  (default) : validate the committed content-addressed bundle at
#                            docs/perf/e2_denominator_bundle_v1/, emit a standard
#                            artifact bundle, and apply the freshness window.
#                            Fail-closed on any contract violation.
#   generate               : (local; needs genuine node+bun) run the
#                            differential-oracle perf arm, then rebuild the
#                            committed bundle from the fresh report. When node/bun
#                            are unavailable, writes a documented degraded receipt
#                            instead of silently passing.
#
# Reproducibility scope (bd-fqlfw.2.6): wall-clock timing is non-deterministic,
# so the byte-identical assertion is the correctness-verdict hash recorded in
# repro.lock.expected_outputs, validated here. Stale denominators are rejected by
# the freshness window (and, in the test suite, by benchmark_freshness_gate.rs via
# tests/e2_denominator_freshness_integration.rs).

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
bundle_dir="${E2_DENOM_BUNDLE_DIR:-docs/perf/e2_denominator_bundle_v1}"
corpus_manifest="${E2_DENOM_CORPUS:-benchmarks/runtime_comparison/manifest.json}"
max_age_days="${E2_DENOM_MAX_AGE_DAYS:-90}"
min_samples="${E2_DENOM_MIN_SAMPLES:-10}"   # DEFAULT_MIN_ACQUISITION_SAMPLES

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${E2_DENOM_ARTIFACT_ROOT:-artifacts/e2_denominator_bundle}"
if [[ "$artifact_root" = /* ]]; then
  run_dir="${artifact_root}/${timestamp}"
else
  run_dir="${root_dir}/${artifact_root}/${timestamp}"
fi
manifest_path="${run_dir}/run_manifest.json"
trace_ids_path="${run_dir}/trace_ids.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
step_logs_dir="${run_dir}/step_logs"
step_log_path="${step_logs_dir}/step_000_e2_denominator_bundle.log"

trace_id="trace-e2-denominator-bundle-${timestamp}"
decision_id="decision-e2-denominator-bundle-${timestamp}"
policy_id="policy-e2-denominator-bundle-v1"
component="e2_denominator_bundle_gate"
bead_id="bd-fqlfw.2.6"
schema_version="franken-engine.e2-denominator-bundle-gate.v1"

mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"
: >"$events_path"
: >"$step_log_path"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: $1 is required" >&2; exit 2; }
}
require_tool jq
require_tool python3
require_tool sha256sum

log() { echo "$*" | tee -a "$step_log_path"; }

git_commit() { git rev-parse HEAD 2>/dev/null || printf 'unknown'; }
dirty_worktree_json() { [[ -n "$(git status --short 2>/dev/null)" ]] && printf 'true' || printf 'false'; }

write_trace_ids() {
  jq -n \
    --arg schema "franken-engine.e2-denominator-bundle-gate.trace-ids.v1" \
    --arg bead_id "$bead_id" --arg component "$component" --arg policy_id "$policy_id" \
    --arg trace_id "$trace_id" --arg decision_id "$decision_id" \
    '{schema_version:$schema, bead_id:$bead_id, component:$component, policy_id:$policy_id,
      trace_ids:[$trace_id], decision_ids:[$decision_id]}' >"$trace_ids_path"
}

write_event() {
  local outcome="$1" error_code="$2" reason="$3" bundle_status="$4"
  jq -nc \
    --arg schema "franken-engine.e2-denominator-bundle-gate.event.v1" \
    --arg trace_id "$trace_id" --arg decision_id "$decision_id" --arg policy_id "$policy_id" \
    --arg component "$component" --arg event "e2_denominator_bundle_${mode}_completed" \
    --arg outcome "$outcome" --arg error_code "$error_code" --arg reason "$reason" \
    --arg bundle_status "$bundle_status" --arg owner_bead "$bead_id" \
    --arg generated_at_utc "$timestamp" \
    '{schema_version:$schema, trace_id:$trace_id, decision_id:$decision_id, policy_id:$policy_id,
      component:$component, event:$event, outcome:$outcome,
      error_code:(if $error_code=="" then null else $error_code end),
      reason:(if $reason=="" then null else $reason end),
      bundle_status:$bundle_status, owner_bead:$owner_bead,
      generated_at_utc:$generated_at_utc}' >>"$events_path"
}

write_run_manifest() {
  local outcome="$1" error_code="$2" reason="$3" bundle_status="$4"
  local commands_json
  commands_json="$(jq -R . "$commands_path" | jq -s .)"
  jq -n \
    --arg schema "franken-engine.proof-artifact-manifest.v1" \
    --arg gate_schema "$schema_version" \
    --arg bead_id "$bead_id" --arg component "$component" --arg mode "$mode" \
    --arg generated_at_utc "$timestamp" --arg git_commit "$(git_commit)" \
    --argjson dirty_worktree "$(dirty_worktree_json)" \
    --arg trace_id "$trace_id" --arg decision_id "$decision_id" --arg policy_id "$policy_id" \
    --arg outcome "$outcome" --arg error_code "$error_code" --arg reason "$reason" \
    --arg bundle_status "$bundle_status" --arg bundle_dir "$bundle_dir" \
    --arg max_age_days "$max_age_days" --arg min_samples "$min_samples" \
    --arg events "$events_path" --arg commands "$commands_path" \
    --arg trace_ids "$trace_ids_path" --arg step_logs_dir "$step_logs_dir" \
    --argjson commands_array "$commands_json" \
    '{schema_version:$schema, gate_schema_version:$gate_schema, bead_id:$bead_id,
      component:$component, mode:$mode, generated_at_utc:$generated_at_utc,
      git_commit:$git_commit, dirty_worktree:$dirty_worktree, trace_id:$trace_id,
      decision_id:$decision_id, policy_id:$policy_id, outcome:$outcome,
      error_code:(if $error_code=="" then null else $error_code end),
      reason:(if $reason=="" then null else $reason end),
      bundle_status:$bundle_status, bundle_dir:$bundle_dir,
      freshness:{max_age_days:($max_age_days|tonumber), min_samples:($min_samples|tonumber)},
      artifacts:{events:$events, commands:$commands, trace_ids:$trace_ids, step_logs_dir:$step_logs_dir},
      commands:$commands_array}' >"$manifest_path"
}

# Bundle status discovered during validation (for manifest reporting).
discovered_status="unknown"

fail() {
  local error_code="$1" reason="$2"
  log "❌ FE-REPRO ${error_code}: ${reason}"
  write_trace_ids
  write_event "fail" "$error_code" "$reason" "$discovered_status"
  write_run_manifest "fail" "$error_code" "$reason" "$discovered_status"
  echo "❌ e2-denominator-bundle gate FAILED (${error_code}): ${reason}" >&2
  exit 1
}

# ----------------------------------------------------------------------------
# validate_bundle: fail-closed contract validation of the committed bundle.
# ----------------------------------------------------------------------------
validate_bundle() {
  local d="$bundle_dir"
  log "Validating committed bundle: $d"

  for f in denominator.json env.json manifest.json repro.lock; do
    [[ -f "$d/$f" ]] || fail "FE-REPRO-0001" "missing required bundle file: $f"
    jq empty "$d/$f" 2>/dev/null || fail "FE-REPRO-0002" "invalid JSON in $f"
  done

  # Schema versions.
  [[ "$(jq -r '.schema_version' "$d/denominator.json")" == "franken-engine.e2-denominator-bundle.v1" ]] \
    || fail "FE-REPRO-0002" "denominator.json schema mismatch"
  [[ "$(jq -r '.schema_version' "$d/env.json")" == "franken-engine.env.v1" ]] \
    || fail "FE-REPRO-0002" "env.json schema mismatch"
  [[ "$(jq -r '.schema_version' "$d/manifest.json")" == "franken-engine.manifest.v1" ]] \
    || fail "FE-REPRO-0002" "manifest.json schema mismatch"
  [[ "$(jq -r '.schema_version' "$d/repro.lock")" == "franken-engine.repro-lock.v1" ]] \
    || fail "FE-REPRO-0002" "repro.lock schema mismatch"

  # Content-addressing: recompute and compare digests recorded in manifest.json.
  local f sha_actual sha_manifest
  for pair in "env:env.json" "lock:repro.lock" "results:denominator.json"; do
    local key="${pair%%:*}" file="${pair#*:}"
    sha_actual="sha256:$(sha256sum "$d/$file" | cut -d' ' -f1)"
    sha_manifest="$(jq -r ".artifacts.${key}.sha256" "$d/manifest.json")"
    [[ "$sha_actual" == "$sha_manifest" ]] \
      || fail "FE-REPRO-0004" "digest mismatch for $file (manifest=$sha_manifest actual=$sha_actual)"
  done

  # repro.lock present beside the artifact (the partner the matrix gate needs).
  [[ -f "$d/repro.lock" ]] || fail "FE-REPRO-0005" "repro.lock partner missing"

  # Correctness-verdict hash binds repro.lock expected_output to denominator.json.
  local cv_lock cv_denom
  cv_lock="$(jq -r '.expected_outputs[0].sha256' "$d/repro.lock")"
  cv_denom="$(jq -r '.correctness_verdict_hash' "$d/denominator.json")"
  [[ "$cv_lock" == "$cv_denom" ]] \
    || fail "FE-REPRO-0005" "correctness_verdict_hash mismatch (lock=$cv_lock denom=$cv_denom)"

  # Recompute the correctness-verdict hash from the verdicts themselves
  # (re-running on the same host must reproduce byte-identical verdicts).
  local cv_recompute
  cv_recompute="sha256:$(jq -S -c '.correctness_verdicts' "$d/denominator.json" \
    | python3 -c 'import sys,json,hashlib;v=json.load(sys.stdin);print(hashlib.sha256((json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+chr(10)).encode()).hexdigest())')"
  [[ "$cv_recompute" == "$cv_denom" ]] \
    || fail "FE-REPRO-0003" "correctness verdicts do not reproduce their recorded hash (got $cv_recompute)"

  # Node/Bun versions must be pinned (non-empty).
  local node_ver bun_ver
  node_ver="$(jq -r '.baselines.node.version' "$d/denominator.json")"
  bun_ver="$(jq -r '.baselines.bun.version' "$d/denominator.json")"
  [[ -n "$node_ver" && "$node_ver" != "null" ]] || fail "FE-REPRO-0005" "node version not pinned"
  [[ -n "$bun_ver"  && "$bun_ver"  != "null" ]] || fail "FE-REPRO-0005" "bun version not pinned"

  discovered_status="$(jq -r '.bundle_status' "$d/denominator.json")"

  # Freshness window: reject stale denominators (FE-REPRO-0007).
  local gen_ns now_ns age_days
  gen_ns="$(jq -r '.generated_unix_ns // 0' "$d/denominator.json")"
  now_ns="$(date -u +%s%N)"
  if [[ "$gen_ns" =~ ^[0-9]+$ && "$gen_ns" -gt 0 ]]; then
    age_days=$(( (now_ns - gen_ns) / 86400000000000 ))
    log "denominator age: ${age_days} day(s) (window: ${max_age_days})"
    if [[ "$age_days" -gt "$max_age_days" ]]; then
      fail "FE-REPRO-0007" "denominator is stale: ${age_days}d > ${max_age_days}d window"
    fi
  else
    fail "FE-REPRO-0007" "denominator missing generated_unix_ns timestamp"
  fi

  # Sample floor (mirrors benchmark_freshness_gate DEFAULT_MIN_ACQUISITION_SAMPLES).
  local samples
  samples="$(jq -r '.measurement.measured_iterations // 0' "$d/denominator.json")"
  if [[ "$samples" -lt "$min_samples" ]]; then
    fail "FE-REPRO-0007" "sample floor unmet: ${samples} < ${min_samples}"
  fi

  # Degraded receipt consistency.
  if [[ "$discovered_status" == "degraded" ]]; then
    [[ -f "$d/degraded_receipt.json" ]] \
      || fail "FE-REPRO-0008" "bundle_status=degraded but no degraded_receipt.json present"
  fi

  log "✓ bundle validated (status=${discovered_status}, node=${node_ver}, bun=${bun_ver}, samples=${samples})"
}

case "$mode" in
  ci|verify)
    {
      echo "# e2-denominator-bundle gate ($mode) @ ${timestamp}"
      echo "validate: $bundle_dir"
    } >>"$commands_path"
    validate_bundle

    # Honest interpretation surface.
    node_meets="$(jq -r '.node_denominator.meets_3x_floor' "$bundle_dir/denominator.json")"
    bun_meets="$(jq -r '.bun_denominator.meets_3x_floor' "$bundle_dir/denominator.json")"
    log "FE-CLAIM-010 floor: node meets_3x=${node_meets}, bun meets_3x=${bun_meets}"

    if [[ "$discovered_status" == "degraded" ]]; then
      log "⚠ bundle is DEGRADED — documented denominator-unavailable receipt; claim stays TARGET."
      write_trace_ids
      write_event "degraded" "FE-REPRO-0007" "denominator degraded receipt present" "$discovered_status"
      write_run_manifest "degraded" "FE-REPRO-0007" "denominator degraded receipt present" "$discovered_status"
      echo "⚠ e2-denominator-bundle gate DEGRADED (documented, not silent-pass)"
      exit 0
    fi

    write_trace_ids
    write_event "pass" "" "" "$discovered_status"
    write_run_manifest "pass" "" "" "$discovered_status"
    log "✅ e2-denominator-bundle gate PASSED (published, fresh, repro.lock-addressed)"
    exit 0
    ;;

  generate)
    node_bin="${E2_DENOM_NODE_BIN:-${NODE:-}}"
    bun_bin="${E2_DENOM_BUN_BIN:-${BUN:-}}"
    [[ -n "$node_bin" ]] || node_bin="$(command -v node || true)"
    [[ -n "$bun_bin" ]] || bun_bin="$(command -v bun || true)"
    fctl="${FRANKENCTL_BIN:-target/release/frankenctl}"
    report_in="${E2_DENOM_REPORT:-}"   # if set, reuse a fresh report instead of running perf

    if [[ -z "$report_in" ]]; then
      if [[ -z "$node_bin" || ! -x "$node_bin" || -z "$bun_bin" || ! -x "$bun_bin" || ! -x "$fctl" ]]; then
        # Degraded: node/bun (or the binary) unavailable -> documented receipt, no silent pass.
        log "node/bun (or frankenctl) unavailable — emitting degraded receipt."
        mkdir -p "$bundle_dir"
        jq -n \
          --arg schema "franken-engine.e2-denominator-degraded-receipt.v1" \
          --arg claim "FE-CLAIM-010" --arg bead "$bead_id" \
          --arg commit "$(git_commit)" --arg generated_at_utc "$timestamp" \
          --arg node "$node_bin" --arg bun "$bun_bin" --arg fctl "$fctl" \
          '{schema_version:$schema, claim_id:$claim, owning_bead:$bead,
            generated_at_utc:$generated_at_utc, source_commit:$commit,
            error_code:"FE-REPRO-0007", verdict:"degraded",
            reasons:["node/bun denominator unavailable on this host",
                     ("node_bin="+$node), ("bun_bin="+$bun), ("frankenctl="+$fctl)],
            policy:"Degraded mode must never promote claim status to observed (docs/REPRODUCIBILITY_CONTRACT.md). FE-CLAIM-010 stays TARGET."}' \
          > "$bundle_dir/degraded_receipt.json"
        echo "# generate: degraded (node/bun unavailable)" >>"$commands_path"
        write_trace_ids
        write_event "degraded" "FE-REPRO-0007" "node/bun unavailable" "degraded"
        write_run_manifest "degraded" "FE-REPRO-0007" "node/bun unavailable" "degraded"
        echo "⚠ e2-denominator-bundle generate: DEGRADED receipt written (node/bun unavailable)"
        exit 0
      fi
      report_in="${run_dir}/report.json"
      local_events="${run_dir}/perf_events.jsonl"
      perf_cmd=("$fctl" differential-oracle perf
        --manifest "$corpus_manifest" --out "$report_in" --events "$local_events"
        --warmup "${E2_DENOM_WARMUP:-3}" --samples "${E2_DENOM_SAMPLES:-10}"
        --case-timeout-ms "${E2_DENOM_CASE_TIMEOUT_MS:-120000}"
        --engine-budget "${E2_DENOM_ENGINE_BUDGET:-2000000000}"
        --node-bin "$node_bin" --bun-bin "$bun_bin")
      printf '%q ' "${perf_cmd[@]}" >>"$commands_path"; echo >>"$commands_path"
      log "Running perf arm (this can take several minutes)..."
      "${perf_cmd[@]}" 2>&1 | tee -a "$step_log_path"
    else
      log "Reusing supplied report: $report_in"
      echo "# generate: reuse report $report_in" >>"$commands_path"
    fi

    rustc_v="$(rustc --version 2>/dev/null || echo unknown)"
    cargo_v="$(${CARGO:-cargo} --version 2>/dev/null || echo unknown)"
    build_cmd=(python3 scripts/build_e2_denominator_bundle.py
      --report "$report_in" --corpus "$corpus_manifest" --out-dir "$bundle_dir"
      --commit "$(git_commit)" --rustc "$rustc_v" --cargo "$cargo_v"
      --generated-at-utc "$timestamp" --dirty "$(dirty_worktree_json)")
    printf '%q ' "${build_cmd[@]}" >>"$commands_path"; echo >>"$commands_path"
    "${build_cmd[@]}" 2>&1 | tee -a "$step_log_path"

    discovered_status="$(jq -r '.bundle_status' "$bundle_dir/denominator.json" 2>/dev/null || echo unknown)"
    write_trace_ids
    write_event "generated" "" "" "$discovered_status"
    write_run_manifest "generated" "" "" "$discovered_status"
    log "✅ bundle generated at $bundle_dir (status=${discovered_status}); now run: $0 ci"
    exit 0
    ;;

  *)
    echo "usage: $0 [ci|verify|generate]" >&2
    exit 2
    ;;
esac
