#!/usr/bin/env bash
set -euo pipefail

# bd-cixqu.14.3 — RGC reproducibility-universality gate (Track N, N.3).
#
# Composes the outputs of N.1 (per-claim `env.json` + `manifest.json` +
# `repro.lock` emission under `docs/evidence/<CLAIM>/`) with N.2
# (`scripts/third_party_repro_lock_verifier.sh`) and emits a single
# "reproducibility-universality verdict" bundle: it proves that EVERY published
# claim-evidence repro.lock in the corpus is consumable by the independent
# third-party verifier — i.e. reproducibility is universal across the corpus,
# not just demonstrated on a hand-picked fixture.
#
# The gate runs the verifier in `--plan-only` mode (validate the lock + derive
# the deterministic replay plan, no execution), so it is fast, hermetic, and
# needs neither cargo nor rch. Fail-closed: any incomplete N.1 triple, any lock
# the verifier rejects, or a corpus smaller than the floor fails the gate.
#
# Scope note (intentional, not a silent omission): the perf/denominator-lineage
# repro.locks (`docs/perf/e2_denominator_bundle_v1`, `benchmarks/runtime_comparison`,
# schema `franken-engine.repro-lock.v1`) use a DIFFERENT reproducibility model —
# they lock the byte-identical correctness-verdict hash while explicitly allowing
# wall-clock timing to vary (`allow_wall_clock=true`), which the strict
# third-party verifier deliberately rejects. They are verified by their own gate
# (`scripts/run_e2_denominator_bundle_gate.sh`) and are out of scope for the
# strict-deterministic universality verdict here.
#
# Logging discipline (bd-cixqu.45): set -euo pipefail; ISO-8601 timestamps;
# sha256 content-hashed entries; LC_ALL=C ordering; no wall-clock in any hashed
# position (timestamps are metadata only).

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

export LC_ALL=C
export LANG=C

mode="${1:-ci}"
case "$mode" in
  ci | verify | run) ;;
  *)
    echo "usage: $0 [ci|verify|run]" >&2
    exit 2
    ;;
esac

schema_version="rgc.reproducibility-universality.gate.run-manifest.v1"
event_schema="rgc.reproducibility-universality.gate.event.v1"
component="rgc_reproducibility_universality_gate"
bead_id="bd-cixqu.14.3"
verifier="scripts/third_party_repro_lock_verifier.sh"
evidence_root="docs/evidence"
min_locks="${RGC_REPRODUCIBILITY_UNIVERSALITY_MIN_LOCKS:-15}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${RGC_REPRODUCIBILITY_UNIVERSALITY_ARTIFACT_ROOT:-artifacts/reproducibility_universality}"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids"
summary_path="${run_dir}/summary.txt"
step_logs_dir="${run_dir}/step_logs"
plans_dir="${run_dir}/plans"

trace_id="trace-${component}-${timestamp}"
decision_id="decision-${component}-${timestamp}"
policy_id="policy-${component}-v1"
replay_command="./scripts/e2e/rgc_reproducibility_universality_replay.sh bundle ${run_dir}"

mkdir -p "$run_dir" "$step_logs_dir" "$plans_dir"
: >"$events_path"
: >"$commands_path"

iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
sha256_of() {
  if [[ -f "$1" ]]; then sha256sum "$1" | awk '{print $1}'; else printf '' | sha256sum | awk '{print $1}'; fi
}
log_command() { printf '%s\n' "$1" >>"$commands_path"; }
# Append one content-hashed structured event (bd-cixqu.45).
log_event() {
  jq -cn \
    --arg schema "$event_schema" \
    --arg ts "$(iso_now)" \
    --arg component "$component" \
    --arg trace_id "$trace_id" \
    --arg event "$1" \
    --arg status "$2" \
    --argjson detail "${3:-{\}}" \
    '{schema_version:$schema, ts:$ts, component:$component, trace_id:$trace_id, event:$event, status:$status, detail:$detail}' \
    >>"$events_path"
  printf '  [%s] %-8s %s\n' "$component" "$2" "$1" >&2
}

# ---- preflight: the N.2 verifier dependency must be present + syntactically valid
if [[ ! -x "$verifier" && ! -f "$verifier" ]]; then
  log_event "preflight" "fail" "$(jq -cn --arg v "$verifier" '{reason:"third-party verifier missing", verifier:$v}')"
  echo "FE-RGC-REPRO-UNIV-0001: missing N.2 verifier ${verifier}" >&2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "FE-RGC-REPRO-UNIV-0002: jq is required" >&2
  exit 2
fi

log_event "begin" "info" "$(jq -cn --arg mode "$mode" --arg run_dir "$run_dir" --arg schema "$schema_version" \
  '{mode:$mode, run_dir:$run_dir, schema:$schema}')"

# ---- verify the N.2 verifier script itself is syntactically valid (it is the
#      engine of every per-lock check; a broken verifier must fail the gate).
verifier_ok=true
log_command "bash -n ${verifier}"
if bash -n "$verifier" >"${step_logs_dir}/00_verifier_bash_n.log" 2>&1; then
  log_event "verifier_bash_n" "pass" "$(jq -cn --arg v "$verifier" '{verifier:$v}')"
else
  verifier_ok=false
  log_event "verifier_bash_n" "fail" "$(jq -cn --arg v "$verifier" '{verifier:$v, hint:"see step_logs/00_verifier_bash_n.log"}')"
fi

# ---- enumerate the N.1 claim-evidence corpus and verify each lock is
#      third-party-verifier-consumable (--plan-only).
results_jsonl="$(mktemp)"
lock_count=0
pass_count=0
fail_count=0
overall_fail=0
step_index=0

while IFS= read -r claim_dir; do
  [[ -n "$claim_dir" ]] || continue
  lock="${claim_dir}/repro.lock"
  [[ -f "$lock" ]] || continue # only N.1 bundle dirs (those carrying a repro.lock)
  claim="$(basename "$claim_dir")"
  lock_count=$((lock_count + 1))
  step_index=$((step_index + 1))

  # N.1 triple completeness (env.json + manifest.json + repro.lock).
  triple_missing=()
  for f in env.json manifest.json repro.lock; do
    [[ -f "${claim_dir}/${f}" ]] || triple_missing+=("$f")
  done

  plan_report="${plans_dir}/${claim}.json"
  step_log="${step_logs_dir}/$(printf '%02d' "$step_index")_${claim}.log"
  cmd_text="${verifier} --lock ${lock} --plan-only --report ${plan_report}"
  log_command "$cmd_text"

  if bash "$verifier" --lock "$lock" --plan-only --report "$plan_report" >"$step_log" 2>&1; then
    vrc=0
  else
    vrc=$?
  fi

  command_count="$(jq -r '.command_count // 0' "$plan_report" 2>/dev/null || echo 0)"
  verdict="$(jq -r '.verdict // "unknown"' "$plan_report" 2>/dev/null || echo unknown)"
  lock_sha="$(sha256_of "$lock")"
  plan_sha="$(sha256_of "$plan_report")"

  status="pass"
  if [[ "$vrc" -ne 0 || "$verdict" != "planned" || ${#triple_missing[@]} -ne 0 ]]; then
    status="fail"
    fail_count=$((fail_count + 1))
    overall_fail=1
  else
    pass_count=$((pass_count + 1))
  fi

  triple_json="$(printf '%s\n' "${triple_missing[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"
  jq -cn \
    --arg claim "$claim" \
    --arg lock "$lock" \
    --arg verdict "$verdict" \
    --argjson rc "$vrc" \
    --argjson command_count "${command_count:-0}" \
    --arg lock_sha256 "$lock_sha" \
    --arg plan_sha256 "$plan_sha" \
    --argjson triple_missing "$triple_json" \
    --arg status "$status" \
    '{claim:$claim, lock:$lock, verdict:$verdict, verifier_rc:$rc, command_count:$command_count, lock_sha256:$lock_sha256, plan_report_sha256:$plan_sha256, triple_missing:$triple_missing, status:$status}' \
    >>"$results_jsonl"

  log_event "verify_lock" "$status" "$(jq -cn --arg claim "$claim" --arg verdict "$verdict" --argjson rc "$vrc" --argjson cc "${command_count:-0}" \
    '{claim:$claim, verdict:$verdict, verifier_rc:$rc, command_count:$cc}')"
done < <(find "$evidence_root" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)

# ---- floor: a "universal" verdict over an empty/tiny corpus is meaningless.
if [[ "$lock_count" -lt "$min_locks" ]]; then
  overall_fail=1
  log_event "corpus_floor" "fail" "$(jq -cn --argjson got "$lock_count" --argjson floor "$min_locks" \
    '{lock_count:$got, min_locks:$floor, reason:"claim-evidence repro.lock corpus below universality floor"}')"
else
  log_event "corpus_floor" "pass" "$(jq -cn --argjson got "$lock_count" --argjson floor "$min_locks" '{lock_count:$got, min_locks:$floor}')"
fi

[[ "$verifier_ok" == true ]] || overall_fail=1

results_array="$(jq -s '.' "$results_jsonl")"
rm -f "$results_jsonl"

outcome="pass"
error_code_json="null"
if [[ "$overall_fail" -ne 0 ]]; then
  outcome="fail"
  error_code_json='"FE-RGC-REPRO-UNIV-GATE-0001"'
fi

log_event "finish" "info" "$(jq -cn --arg outcome "$outcome" --argjson locks "$lock_count" --argjson pass "$pass_count" --argjson fail "$fail_count" \
  '{outcome:$outcome, lock_count:$locks, pass:$pass, fail:$fail}')"

git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then dirty_worktree=false; else dirty_worktree=true; fi

cat >"$trace_ids_path" <<EOF
trace_id=${trace_id}
decision_id=${decision_id}
policy_id=${policy_id}
EOF

{
  printf 'RGC reproducibility-universality verdict\n'
  printf '========================================\n'
  printf 'generated_at_utc : %s\n' "$timestamp"
  printf 'git_commit       : %s\n' "$git_commit"
  printf 'outcome          : %s\n' "$outcome"
  printf 'corpus           : %s (docs/evidence/*/repro.lock, N.1 per-claim emission)\n' "$evidence_root"
  printf 'locks checked    : %s (floor %s)\n' "$lock_count" "$min_locks"
  printf 'verifier-consumable : %s pass / %s fail\n' "$pass_count" "$fail_count"
  printf 'verifier         : %s (--plan-only)\n' "$verifier"
  printf '\nEvery lock above was validated + had its deterministic replay plan derived\n'
  printf 'by the independent third-party verifier. Perf/denominator-lineage locks\n'
  printf '(franken-engine.repro-lock.v1) use a distinct correctness-verdict model and\n'
  printf 'are out of scope (see run_e2_denominator_bundle_gate.sh).\n'
} >"$summary_path"

events_sha="$(sha256_of "$events_path")"
commands_sha="$(sha256_of "$commands_path")"
summary_sha="$(sha256_of "$summary_path")"

jq -n \
  --arg schema_version "$schema_version" \
  --arg bead_id "$bead_id" \
  --arg component "$component" \
  --arg mode "$mode" \
  --arg generated_at_utc "$timestamp" \
  --arg git_commit "$git_commit" \
  --argjson dirty_worktree "$dirty_worktree" \
  --arg trace_id "$trace_id" \
  --arg decision_id "$decision_id" \
  --arg policy_id "$policy_id" \
  --arg outcome "$outcome" \
  --argjson error_code "$error_code_json" \
  --arg evidence_root "$evidence_root" \
  --argjson lock_count "$lock_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson min_locks "$min_locks" \
  --argjson verifier_ok "$verifier_ok" \
  --arg verifier "$verifier" \
  --argjson results "$results_array" \
  --arg manifest "$manifest_path" \
  --arg events "$events_path" \
  --arg commands "$commands_path" \
  --arg trace_ids "$trace_ids_path" \
  --arg summary "$summary_path" \
  --arg step_logs "$step_logs_dir" \
  --arg plans "$plans_dir" \
  --arg events_sha256 "$events_sha" \
  --arg commands_sha256 "$commands_sha" \
  --arg summary_sha256 "$summary_sha" \
  --arg replay_command "$replay_command" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    component: $component,
    mode: $mode,
    generated_at_utc: $generated_at_utc,
    git_commit: $git_commit,
    dirty_worktree: $dirty_worktree,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    outcome: $outcome,
    error_code: $error_code,
    corpus: {
      evidence_root: $evidence_root,
      lock_count: $lock_count,
      pass_count: $pass_count,
      fail_count: $fail_count,
      min_locks: $min_locks,
      verifier: $verifier,
      verifier_syntax_ok: $verifier_ok,
      verifier_mode: "plan-only"
    },
    results: $results,
    content_hashes: {
      events_jsonl: $events_sha256,
      commands_txt: $commands_sha256,
      summary_txt: $summary_sha256
    },
    artifacts: {
      manifest: $manifest,
      events: $events,
      commands: $commands,
      trace_ids: $trace_ids,
      summary: $summary,
      step_logs: $step_logs,
      plans: $plans
    },
    operator_verification: [
      ("cat " + $manifest),
      ("cat " + $summary),
      ("cat " + $events),
      ("ls " + $plans),
      $replay_command
    ],
    replay_command: $replay_command
  }' >"${manifest_path}.tmp"
mv "${manifest_path}.tmp" "$manifest_path"

echo "rgc reproducibility-universality manifest: ${manifest_path}"
echo "rgc reproducibility-universality summary:  ${summary_path}"
echo "outcome=${outcome} locks=${lock_count} pass=${pass_count} fail=${fail_count}"

[[ "$overall_fail" -eq 0 ]]
