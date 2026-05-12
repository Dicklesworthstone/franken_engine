#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SOURCE_LOCAL_RCH_PROOF_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-source-local-rch-proof}"
run_id="${SOURCE_LOCAL_RCH_PROOF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SOURCE_LOCAL_RCH_PROOF_RUN_DIR:-${artifact_root}/${run_id}}"

package="${SOURCE_LOCAL_RCH_PROOF_PACKAGE:-frankenengine-engine}"
target_kind="${SOURCE_LOCAL_RCH_PROOF_TARGET_KIND:-lib}"
test_filter="${SOURCE_LOCAL_RCH_PROOF_TEST_FILTER:-shadow_decision_composer::tests::output_dir_file_lock_blocks_second_writer_until_release}"
covered_path="${SOURCE_LOCAL_RCH_PROOF_COVERED_PATH:-crates/franken-engine/src/shadow_decision_composer.rs}"
target_dir="${SOURCE_LOCAL_RCH_PROOF_TARGET_DIR:-/tmp/rch_target_franken_engine_source_local_bd_lnks9}"
rustflags="${RUSTFLAGS:--Clinker=cc}"
timeout_seconds="${SOURCE_LOCAL_RCH_PROOF_TIMEOUT_SECONDS:-1800}"

request_json="${run_dir}/request.json"
proof_admission_json="${run_dir}/proof_admission.json"
sticky_plan_json="${run_dir}/sticky_plan.json"
admission_dir="${run_dir}/admission"
preflight_dir="${run_dir}/preflight"
preflight_json="${preflight_dir}/preflight_report.json"
rch_log="${run_dir}/rch-output.log"
log_scan_json="${run_dir}/log_scan.json"
manifest_json="${run_dir}/run_manifest.json"
events_jsonl="${run_dir}/events.jsonl"
commands_txt="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/source_local_rch_admission_no_mock_proof.sh

Runs one live source-local lib-unit proof through the source-local admission
composer and rch. The script writes replayable artifacts and refuses local
fallback or frankenengine-test-support compile contamination.
EOF
}

case "${1:-run}" in
  run)
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 64
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for source-local rch no-mock proof\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for source-local rch no-mock proof\n' >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  printf 'timeout is required for source-local rch no-mock proof\n' >&2
  exit 2
fi

mkdir -p "$run_dir" "$preflight_dir" "$admission_dir"
for artifact_path in "$request_json" "$proof_admission_json" "$sticky_plan_json" "$rch_log" "$log_scan_json" "$manifest_json" "$events_jsonl" "$commands_txt" "$report_md"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_jsonl"
: >"$commands_txt"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.source-local-rch-no-mock-proof.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail}' >>"$events_jsonl"
}

source_revision="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)"
source_hash="$(sha256sum "${repo_root}/${covered_path}" | awk '{print $1}')"
cargo_lock_hash="$(sha256sum "${repo_root}/Cargo.lock" | awk '{print $1}')"
dependency_root_hash="$(printf '%s\n%s\n%s\n%s\n' "$source_hash" "$cargo_lock_hash" "$package" "$target_kind" | sha256sum | awk '{print $1}')"
cargo_command="cargo test -p ${package} --${target_kind} ${test_filter} -- --exact --nocapture"
rch_command="rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=${target_dir} RUSTFLAGS=$(printf '%q' "$rustflags") ${cargo_command}"
command_fingerprint="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n' "$source_revision" "$cargo_lock_hash" "$dependency_root_hash" "$target_dir" "$rustflags" "$cargo_command" | sha256sum | awk '{print $1}')"

jq -n \
  --arg schema_version "franken-engine.source-local-rch-validation-request.v1" \
  --arg case_id "bd-lnks9-live" \
  --arg source_revision "$source_revision" \
  --arg source_hash "$source_hash" \
  --arg cargo_lock_hash "$cargo_lock_hash" \
  --arg dependency_root_hash "$dependency_root_hash" \
  --arg package "$package" \
  --arg target_kind "$target_kind" \
  --arg test_filter "$test_filter" \
  --arg cargo_command "$cargo_command" \
  --arg rustflags "$rustflags" \
  --arg toolchain "default" \
  --arg cargo_target_dir "$target_dir" \
  --arg command_fingerprint "$command_fingerprint" \
  --arg covered_path "$covered_path" \
  --arg cold_refresh_command "$rch_command" \
  '{
    schema_version:$schema_version,
    case_id:$case_id,
    source_revision:$source_revision,
    source_hash:$source_hash,
    cargo_lock_hash:$cargo_lock_hash,
    dependency_root_hash:$dependency_root_hash,
    package:$package,
    target_kind:$target_kind,
    test_filter:$test_filter,
    cargo_command:$cargo_command,
    rustflags:$rustflags,
    toolchain:$toolchain,
    cargo_target_dir:$cargo_target_dir,
    command_fingerprint:$command_fingerprint,
    changed_paths:[],
    covered_paths:[$covered_path],
    cold_refresh_command:$cold_refresh_command,
    reusable_rch_command:$cold_refresh_command,
    local_fallback_observed:false,
    support_crate_contamination_observed:false
  }' >"$request_json"

jq -n \
  --arg schema_version "franken-engine.proof-reuse-admission-bundle.v1" \
  --arg source_revision "$source_revision" \
  --arg source_hash "$source_hash" \
  --arg cargo_lock_hash "$cargo_lock_hash" \
  --arg dependency_root_hash "$dependency_root_hash" \
  --arg package "$package" \
  --arg target_kind "$target_kind" \
  --arg test_filter "$test_filter" \
  --arg rustflags "$rustflags" \
  --arg toolchain "default" \
  --arg cargo_target_dir "$target_dir" \
  --arg command_fingerprint "$command_fingerprint" \
  --arg covered_path "$covered_path" \
  '{
    schema_version:$schema_version,
    admission_decision:"refresh_required",
    admission_rows:[
      {
        artifact_id:"bd-lnks9-live-cold-refresh",
        classification:"refresh_required",
        deterministic_reasons:["no preserved reusable proof artifact for this exact request identity"],
        request_identity:{
          source_revision:$source_revision,
          source_hash:$source_hash,
          cargo_lock_hash:$cargo_lock_hash,
          dependency_root_hash:$dependency_root_hash,
          package:$package,
          target_kind:$target_kind,
          test_filter:$test_filter,
          rustflags:$rustflags,
          toolchain:$toolchain,
          cargo_target_dir:$cargo_target_dir,
          command_fingerprint:$command_fingerprint
        },
        covered_paths:[$covered_path],
        compatibility:{
          local_fallback_observed:false,
          support_crate_contamination_observed:false
        }
      }
    ]
  }' >"$proof_admission_json"

jq -n \
  --arg schema_version "franken-engine.sticky-worker-warm-target-lease-plan.v1" \
  '{
    schema_version:$schema_version,
    plan_decision:"missing",
    assigned_worker_id:null,
    assigned_target_dir:null,
    phase_plans:[],
    local_fallback_marker_count:0
  }' >"$sticky_plan_json"

write_event "request.created" "ok" "$request_json"

"${repo_root}/scripts/swarm_proof_command_preflight.sh" \
  --case-id "bd-lnks9-live" \
  --bead-id "bd-lnks9" \
  --command "$rch_command" \
  --output-dir "$preflight_dir" >>"$commands_txt"
write_event "preflight.completed" "ok" "$preflight_json"

set +e
"${repo_root}/scripts/source_local_rch_validation_admission.sh" \
  --case-id "bd-lnks9-live" \
  --request-json "$request_json" \
  --preflight-json "$preflight_json" \
  --proof-admission-json "$proof_admission_json" \
  --sticky-plan-json "$sticky_plan_json" \
  --output-dir "$admission_dir" >>"$commands_txt" 2>"${run_dir}/admission.stderr"
admission_exit=$?
set -e
admission_json="${admission_dir}/source_local_rch_validation_admission.json"
admission_decision="$(jq -r '.admission_decision' "$admission_json")"
if [[ "$admission_exit" -ne 75 || "$admission_decision" != "cold_refresh_required" ]]; then
  printf 'expected cold_refresh_required admission, got exit=%s decision=%s\n' "$admission_exit" "$admission_decision" >&2
  exit 42
fi
write_event "admission.completed" "$admission_decision" "$admission_json"

printf '%s\n' "$rch_command" >>"$commands_txt"
set +e
timeout "$timeout_seconds" \
  rch exec -- env \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=1 \
    "CARGO_TARGET_DIR=${target_dir}" \
    "RUSTFLAGS=${rustflags}" \
    cargo test -p "$package" "--${target_kind}" "$test_filter" -- --exact --nocapture \
  >"$rch_log" 2>&1
remote_exit=$?
set -e

support_detected=false
fallback_detected=false
if grep -Eiq '(^|[[:space:]])(Compiling|Checking|Fresh|Dirty)[[:space:]]+frankenengine-test-support([[:space:]]|$)' "$rch_log"; then
  support_detected=true
fi
if grep -Eiq 'Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \(|running locally' "$rch_log"; then
  fallback_detected=true
fi
strip_ansi() {
  sed -E $'s/\x1B\\[[0-9;]*[[:alpha:]]//g'
}
plain_log="${run_dir}/rch-output.plain.log"
strip_ansi <"$rch_log" >"$plain_log"
compile_timing="$(grep -E 'Finished .* profile .*target\(s\) in' "$plain_log" | tail -n 1 || true)"
test_result="$(grep -E 'test result:' "$plain_log" | tail -n 1 || true)"
remote_finished="$(grep -E 'Remote command finished:' "$plain_log" | tail -n 1 || true)"

jq -n \
  --arg schema_version "franken-engine.source-local-rch-log-scan.v1" \
  --argjson remote_exit "$remote_exit" \
  --arg support_detected "$support_detected" \
  --arg fallback_detected "$fallback_detected" \
  --arg compile_timing "$compile_timing" \
  --arg test_result "$test_result" \
  --arg remote_finished "$remote_finished" \
  --arg rch_log "$rch_log" \
  --arg plain_log "$plain_log" \
  '{
    schema_version:$schema_version,
    remote_exit:$remote_exit,
    support_crate_contamination_detected:($support_detected == "true"),
    local_fallback_detected:($fallback_detected == "true"),
    compile_timing:$compile_timing,
    test_result:$test_result,
    remote_finished:$remote_finished,
    rch_log:$rch_log,
    plain_log:$plain_log
  }' >"$log_scan_json"

status="pass"
exit_code=0
if [[ "$support_detected" == "true" || "$fallback_detected" == "true" ]]; then
  status="fail_closed"
  exit_code=42
elif [[ "$remote_exit" -ne 0 ]]; then
  status="remote_blocker"
  exit_code=75
fi

jq -n \
  --arg schema_version "franken-engine.source-local-rch-no-mock-proof-manifest.v1" \
  --arg bead_id "bd-lnks9" \
  --arg status "$status" \
  --arg admission_decision "$admission_decision" \
  --arg package "$package" \
  --arg target_kind "$target_kind" \
  --arg test_filter "$test_filter" \
  --arg target_dir "$target_dir" \
  --arg source_revision "$source_revision" \
  --arg command_fingerprint "$command_fingerprint" \
  --arg request_json "$request_json" \
  --arg preflight_json "$preflight_json" \
  --arg admission_json "$admission_json" \
  --arg log_scan_json "$log_scan_json" \
  --arg rch_log "$rch_log" \
  --arg events_jsonl "$events_jsonl" \
  --arg commands_txt "$commands_txt" \
  --arg report_md "$report_md" \
  --argjson remote_exit "$remote_exit" \
  --argjson exit_code "$exit_code" \
  '{
    schema_version:$schema_version,
    bead_id:$bead_id,
    status:$status,
    exit_code:$exit_code,
    remote_exit:$remote_exit,
    admission_decision:$admission_decision,
    request:{
      package:$package,
      target_kind:$target_kind,
      test_filter:$test_filter,
      target_dir:$target_dir,
      source_revision:$source_revision,
      command_fingerprint:$command_fingerprint
    },
    artifact_paths:{
      request_json:$request_json,
      preflight_json:$preflight_json,
      admission_json:$admission_json,
      log_scan_json:$log_scan_json,
      rch_log:$rch_log,
      events_jsonl:$events_jsonl,
      commands_txt:$commands_txt,
      report_md:$report_md
    }
  }' >"$manifest_json"

write_event "rch.completed" "$status" "$log_scan_json"

{
  printf '# Source-Local RCH Admission No-Mock Proof\n\n'
  printf -- "- Status: \`%s\`\n" "$status"
  printf -- "- Admission decision: \`%s\`\n" "$admission_decision"
  printf -- "- Remote exit: \`%s\`\n" "$remote_exit"
  printf -- "- Target dir: \`%s\`\n" "$target_dir"
  printf -- "- Compile timing: %s\n" "$compile_timing"
  printf -- "- Test result: %s\n" "$test_result"
  printf -- "- Remote finished: %s\n" "$remote_finished"
  printf -- "- Support crate contamination: \`%s\`\n" "$support_detected"
  printf -- "- Local fallback: \`%s\`\n" "$fallback_detected"
  printf -- "- RCH log: \`%s\`\n" "$rch_log"
} >"$report_md"

printf 'source_local_rch_no_mock_manifest=%s\n' "$manifest_json"
printf 'source_local_rch_no_mock_status=%s\n' "$status"
exit "$exit_code"
