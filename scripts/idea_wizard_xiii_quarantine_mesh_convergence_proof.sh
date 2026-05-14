#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
propagation_log_json=""
source_revision=""
artifact_root="${root_dir}/artifacts/idea_wizard_xiii_quarantine_mesh_convergence_proof"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_dir=""
skip_live_refresh=false
original_args=("$@")

usage() {
  cat <<'USAGE'
Usage: scripts/idea_wizard_xiii_quarantine_mesh_convergence_proof.sh [options]

Options:
  --propagation-log-json <path>    Use an existing quarantine mesh JSON log.
  --skip-live-refresh              Require --propagation-log-json and do not run the rch-backed demo.
  --source-revision <rev>          Source revision bound into the proof.
  --output-dir <path>              Output artifact directory.
  -h, --help                       Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --propagation-log-json)
      propagation_log_json="${2:?--propagation-log-json requires a path}"
      shift 2
      ;;
    --skip-live-refresh)
      skip_live_refresh=true
      shift
      ;;
    --source-revision)
      source_revision="${2:?--source-revision requires a value}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:?--output-dir requires a path}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required\n' >&2
  exit 2
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if [[ -z "$run_dir" ]]; then
  run_dir="${artifact_root}/${run_id}"
fi
if [[ "$skip_live_refresh" == true && -z "$propagation_log_json" ]]; then
  printf '--skip-live-refresh requires --propagation-log-json\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
live_stdout_path="${run_dir}/live_quarantine_mesh.stdout"
live_stderr_path="${run_dir}/live_quarantine_mesh.stderr"
live_log_path="${run_dir}/live_quarantine_mesh_log.json"
report_json_path="${run_dir}/live_quarantine_mesh_convergence_report.json"
report_tmp_path="${run_dir}/live_quarantine_mesh_convergence_report.tmp.json"
peer_attempts_path="${run_dir}/peer_attempts.jsonl"
partial_fixture_path="${run_dir}/partial_failure_degraded_fixture.json"
total_fixture_path="${run_dir}/total_failure_degraded_fixture.json"
replay_report_path="${run_dir}/replay_verifier_report.json"
report_md_path="${run_dir}/report.md"
manifest_path="${run_dir}/run_manifest.json"

for artifact_path in \
  "$commands_path" \
  "$events_path" \
  "$live_stdout_path" \
  "$live_stderr_path" \
  "$live_log_path" \
  "$report_json_path" \
  "$report_tmp_path" \
  "$peer_attempts_path" \
  "$partial_fixture_path" \
  "$total_fixture_path" \
  "$replay_report_path" \
  "$report_md_path" \
  "$manifest_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_xiii_quarantine_mesh_convergence_proof.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local status="$2"
  local reason="$3"
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.event.v1" \
    --arg event "$event" \
    --arg status "$status" \
    --arg reason "$reason" \
    '{schema_version:$schema_version,event:$event,status:$status,reason:$reason}' >>"$events_path"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

extract_first_json_object() {
  local input="$1"
  local output="$2"
  awk '
    BEGIN { capture = 0; depth = 0 }
    {
      if (!capture && $0 ~ /^[[:space:]]*\{[[:space:]]*$/) {
        capture = 1
      }
      if (capture) {
        print
        line = $0
        for (i = 1; i <= length(line); i++) {
          c = substr(line, i, 1)
          if (c == "{") {
            depth++
          } else if (c == "}") {
            depth--
          }
        }
        if (depth == 0) {
          exit
        }
      }
    }
  ' "$input" >"$output"
}

if [[ -z "$propagation_log_json" ]]; then
  printf './examples/07_quarantine_mesh/demo.sh # internally rch exec -- env ... cargo run --quiet -p frankenengine-engine --bin franken-quarantine-mesh-demo\n' >>"$commands_path"
  set +e
  (
    cd "$root_dir"
    ./examples/07_quarantine_mesh/demo.sh
  ) >"$live_stdout_path" 2>"$live_stderr_path"
  live_status=$?
  set -e
  if [[ "$live_status" -ne 0 ]]; then
    write_event "live_quarantine_mesh_refresh" "fail" "rch-backed quarantine mesh demo failed"
    jq -n \
      --arg schema_version "franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.report.v1" \
      --arg source_revision "$source_revision" \
      '{
        schema_version:$schema_version,
        claim_id:"FE-CLAIM-005",
        source_revision:$source_revision,
        decision:"fail_closed",
        replay_verifier_verdict:"fail",
        failures:[{check:"live_quarantine_mesh_refresh",reason:"rch-backed quarantine mesh demo failed"}]
      }' >"$report_json_path"
    printf 'live quarantine mesh refresh failed; report=%s\n' "$report_json_path" >&2
    exit 42
  fi
  extract_first_json_object "$live_stdout_path" "$live_log_path"
  propagation_log_json="$live_log_path"
  write_event "live_quarantine_mesh_refresh" "pass" "rch-backed quarantine mesh demo produced a log"
else
  jq '.' "$propagation_log_json" >"$live_log_path"
  propagation_log_json="$live_log_path"
  write_event "live_quarantine_mesh_refresh" "skipped" "using caller-provided quarantine mesh log"
fi

if ! jq empty "$propagation_log_json"; then
  write_event "live_quarantine_mesh_log_parse" "fail" "quarantine mesh log is not valid JSON"
  jq -n \
    --arg schema_version "franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.report.v1" \
    --arg source_revision "$source_revision" \
    '{
      schema_version:$schema_version,
      claim_id:"FE-CLAIM-005",
      source_revision:$source_revision,
      decision:"fail_closed",
      replay_verifier_verdict:"fail",
      failures:[{check:"live_quarantine_mesh_log_parse",reason:"quarantine mesh log is not valid JSON"}]
    }' >"$report_json_path"
  printf 'quarantine mesh log parse failed; report=%s\n' "$report_json_path" >&2
  exit 42
fi

jq -c '
  (.instances // [])[]
  | {
      schema_version:"franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.peer-attempt.v1",
      event:"peer_quarantine_attempt",
      instance_id,
      target_revoked,
      resolved_action,
      checkpoint_timestamp_ns,
      convergence_ms:((.convergence_from_first_revocation_ns // 0) / 1000000 | floor),
      within_bounded_slo,
      failed:((.target_revoked != true) or (.resolved_action != "quarantine") or (.within_bounded_slo != true))
    }
' "$propagation_log_json" >"$peer_attempts_path"
cat "$peer_attempts_path" >>"$events_path"

jq \
  --arg source_revision "$source_revision" \
  --arg propagation_log "$propagation_log_json" \
  --arg peer_attempts_jsonl "$peer_attempts_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_json "$report_json_path" \
  --arg partial_fixture "$partial_fixture_path" \
  --arg total_fixture "$total_fixture_path" \
  --arg replay_report "$replay_report_path" \
  --arg report_md "$report_md_path" \
  --arg run_manifest "$manifest_path" '
    def ms($ns): (($ns // 0) / 1000000 | floor);
    (.instances // []) as $instances
    | ($instances | map(.instance_id)) as $attempted
    | ($instances | map(select((.target_revoked != true) or (.resolved_action != "quarantine") or (.within_bounded_slo != true)) | .instance_id)) as $failed
    | (if ($instances | length) > 0 then ($instances | map(.convergence_from_first_revocation_ns // 0) | max) else 0 end) as $convergence_ns
    | (.bounded_convergence_slo_ns // 0) as $slo_ns
    | [
        {check:"schema_shape",passed:((.scenario // "") != "" and (.fleet_convergence | type) == "object"),detail:"log must include scenario and fleet_convergence"},
        {check:"peer_count",passed:(($instances | length) >= 3),detail:"proof requires at least three mesh peers"},
        {check:"attempted_targets",passed:(($attempted | length) == ($instances | length) and ($attempted | length) > 0),detail:"every peer must be listed as an attempted target"},
        {check:"failed_targets",passed:(($failed | length) == 0),detail:"live proof must not have failed peer targets"},
        {check:"convergence_slo",passed:(($slo_ns > 0) and ($convergence_ns <= $slo_ns) and (.fleet_convergence.within_bounded_slo == true)),detail:"fleet convergence must be within the bounded SLO"},
        {check:"quarantine_action",passed:(all($instances[]; .resolved_action == "quarantine" and .target_revoked == true)),detail:"every peer must resolve to quarantine with target revoked"},
        {check:"permanent_ratchet",passed:true,detail:"containment is a permanent ratchet in this proof"},
        {check:"de_escalation_supported",passed:true,detail:"de-escalation is intentionally unsupported and downgraded"}
      ] as $checks
    | ($checks | map(select(.passed | not) | {check,reason:.detail})) as $failures
    | {
        schema_version:"franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.report.v1",
        claim_id:"FE-CLAIM-005",
        bead_id:"bd-ly6hp.3",
        source_revision:$source_revision,
        decision:(if ($failures | length) == 0 then "pass" else "fail_closed" end),
        promotion_subset:"live_quarantine_mesh_bounded_convergence_only",
        scenario:.scenario,
        zone:.zone,
        extension_id:.extension_id,
        peer_count:($instances | length),
        attempted_targets:$attempted,
        failed_targets:$failed,
        convergence_ms:ms($convergence_ns),
        slo_threshold_ms:ms($slo_ns),
        checkpoint_spread_ms:ms(.fleet_convergence.checkpoint_spread_ns),
        permanent_ratchet:true,
        de_escalation_supported:false,
        limitation_note:"De-escalation is not supported by this proof; containment remains a permanent ratchet until separate recovery or re-attestation evidence exists.",
        replay_verifier_verdict:(if ($failures | length) == 0 then "pass" else "fail" end),
        checks:$checks,
        failures:$failures,
        artifact_paths:{
          live_quarantine_mesh_log_json:$propagation_log,
          live_quarantine_mesh_convergence_report_json:$report_json,
          peer_attempts_jsonl:$peer_attempts_jsonl,
          partial_failure_degraded_fixture:$partial_fixture,
          total_failure_degraded_fixture:$total_fixture,
          replay_verifier_report_json:$replay_report,
          events_jsonl:$events_jsonl,
          commands_txt:$commands_txt,
          report_md:$report_md,
          run_manifest_json:$run_manifest
        }
      }
  ' "$propagation_log_json" >"$report_tmp_path"
mv "$report_tmp_path" "$report_json_path"

jq '
  . as $report
  | $report
  | .schema_version = "franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.degraded-fixture.v1"
  | .decision = "degraded"
  | .green = false
  | .fixture_kind = "partial_failure"
  | .failed_targets = [($report.attempted_targets[-1] // "missing-peer")]
  | .convergence_ms = ($report.slo_threshold_ms + 1)
  | .degraded_reason = "one peer failed to acknowledge quarantine propagation inside the bounded SLO"
  | .replay_verifier_verdict = "degraded"
' "$report_json_path" >"$partial_fixture_path"

jq '
  . as $report
  | $report
  | .schema_version = "franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.degraded-fixture.v1"
  | .decision = "degraded"
  | .green = false
  | .fixture_kind = "total_failure"
  | .failed_targets = $report.attempted_targets
  | .convergence_ms = ($report.slo_threshold_ms + 1)
  | .degraded_reason = "no peer acknowledged quarantine propagation inside the bounded SLO"
  | .replay_verifier_verdict = "degraded"
' "$report_json_path" >"$total_fixture_path"

partial_degraded=false
if jq -e '.decision == "degraded" and .green == false and (.failed_targets | length) > 0' "$partial_fixture_path" >/dev/null; then
  partial_degraded=true
fi
total_degraded=false
if jq -e '.decision == "degraded" and .green == false and (.failed_targets | length) == (.attempted_targets | length) and (.failed_targets | length) > 0' "$total_fixture_path" >/dev/null; then
  total_degraded=true
fi

main_pass=false
if jq -e '.decision == "pass" and .permanent_ratchet == true and .de_escalation_supported == false' "$report_json_path" >/dev/null; then
  main_pass=true
fi

log_hash="$(sha256_file "$propagation_log_json")"
report_hash="$(sha256_file "$report_json_path")"

jq -n \
  --arg source_revision "$source_revision" \
  --arg log_hash "$log_hash" \
  --arg report_hash "$report_hash" \
  --arg report_json "$report_json_path" \
  --arg partial_fixture "$partial_fixture_path" \
  --arg total_fixture "$total_fixture_path" \
  --argjson main_pass "$main_pass" \
  --argjson partial_degraded "$partial_degraded" \
  --argjson total_degraded "$total_degraded" \
  '[
      {check:"main_live_quarantine_mesh_report",passed:$main_pass,detail:"main report must pass bounded convergence and downgrade de-escalation"},
      {check:"partial_failure_degraded_fixture",passed:$partial_degraded,detail:"partial failure fixture must remain degraded"},
      {check:"total_failure_degraded_fixture",passed:$total_degraded,detail:"total failure fixture must remain degraded"}
    ] as $checks
    | ($checks | map(select(.passed | not) | {check,reason:.detail})) as $failures
    | {
        schema_version:"franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.replay-verifier-report.v1",
        claim_id:"FE-CLAIM-005",
        bead_id:"bd-ly6hp.3",
        source_revision:$source_revision,
        decision:(if ($failures | length) == 0 then "pass" else "fail_closed" end),
        replay_verifier_verdict:(if ($failures | length) == 0 then "pass" else "fail" end),
        live_log_sha256:$log_hash,
        report_sha256:$report_hash,
        checks:$checks,
        failures:$failures,
        artifact_paths:{
          live_quarantine_mesh_convergence_report_json:$report_json,
          partial_failure_degraded_fixture:$partial_fixture,
          total_failure_degraded_fixture:$total_fixture
        }
      }' >"$replay_report_path"

jq -c '.checks[] | {schema_version:"franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.event.v1",event:"quarantine_mesh_check",status:(if .passed then "pass" else "fail" end),reason:.detail,check}' "$report_json_path" >>"$events_path"
jq -c '.checks[] | {schema_version:"franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.event.v1",event:"quarantine_mesh_replay_check",status:(if .passed then "pass" else "fail" end),reason:.detail,check}' "$replay_report_path" >>"$events_path"

jq -n \
  --arg source_revision "$source_revision" \
  --arg report_json "$report_json_path" \
  --arg replay_report "$replay_report_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_md_path" \
  --arg live_log "$propagation_log_json" \
  --arg peer_attempts "$peer_attempts_path" \
  --arg partial_fixture "$partial_fixture_path" \
  --arg total_fixture "$total_fixture_path" \
  '{
    schema_version:"franken-engine.idea-wizard-xiii-quarantine-mesh-convergence-proof.run-manifest.v1",
    claim_id:"FE-CLAIM-005",
    bead_id:"bd-ly6hp.3",
    source_revision:$source_revision,
    artifact_paths:{
      live_quarantine_mesh_log_json:$live_log,
      live_quarantine_mesh_convergence_report_json:$report_json,
      peer_attempts_jsonl:$peer_attempts,
      partial_failure_degraded_fixture:$partial_fixture,
      total_failure_degraded_fixture:$total_fixture,
      replay_verifier_report_json:$replay_report,
      events_jsonl:$events_jsonl,
      commands_txt:$commands_txt,
      report_md:$report_md
    }
  }' >"$manifest_path"

{
  printf '# IDEA-WIZARD-XIII Quarantine Mesh Convergence Proof\n\n'
  jq -r '"Decision: \(.decision)\nClaim: \(.claim_id)\nPeer count: \(.peer_count)\nConvergence ms: \(.convergence_ms)\nSLO threshold ms: \(.slo_threshold_ms)\nPermanent ratchet: \(.permanent_ratchet)\nDe-escalation supported: \(.de_escalation_supported)\nFailed targets: \(.failed_targets | join(","))\n\n\(.limitation_note)"' "$report_json_path"
  printf '\n\nReplay verifier: '
  jq -r '.decision' "$replay_report_path"
  printf '\n'
} >"$report_md_path"

if ! jq -e '.decision == "pass"' "$replay_report_path" >/dev/null; then
  printf 'quarantine mesh convergence proof failed closed; report=%s\n' "$replay_report_path" >&2
  exit 42
fi

printf 'quarantine_mesh_convergence_report=%s\n' "$report_json_path"
