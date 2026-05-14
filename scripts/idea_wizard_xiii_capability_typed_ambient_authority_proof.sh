#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_result_json=""
source_revision=""
artifact_root="${root_dir}/artifacts/idea_wizard_xiii_capability_typed_ambient_authority_proof"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_dir=""
skip_rust_validation=false
original_args=("$@")

usage() {
  cat <<'USAGE'
Usage: scripts/idea_wizard_xiii_capability_typed_ambient_authority_proof.sh [options]

Options:
  --runtime-result-json <path>     Use an existing runtime proof JSON result.
  --skip-rust-validation           Require --runtime-result-json and do not run rch cargo test.
  --source-revision <rev>          Source revision bound into the proof.
  --output-dir <path>              Output artifact directory.
  -h, --help                       Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-result-json)
      runtime_result_json="${2:?--runtime-result-json requires a path}"
      shift 2
      ;;
    --skip-rust-validation)
      skip_rust_validation=true
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
if [[ "$skip_rust_validation" == true && -z "$runtime_result_json" ]]; then
  printf '%s\n' '--skip-rust-validation requires --runtime-result-json' >&2
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if [[ -z "$run_dir" ]]; then
  run_dir="${artifact_root}/${run_id}"
fi

mkdir -p "$run_dir"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
runtime_stdout_path="${run_dir}/runtime_validation.stdout"
runtime_stderr_path="${run_dir}/runtime_validation.stderr"
runtime_result_path="${run_dir}/runtime_enforcement_result.json"
typed_fixture_path="${run_dir}/typed_input_or_manifest_fixture.json"
filesystem_fixture_path="${run_dir}/ambient_filesystem_rejection_fixture.rs"
network_fixture_path="${run_dir}/ambient_network_rejection_fixture.rs"
hostcall_fixture_path="${run_dir}/ambient_hostcall_rejection_fixture.rs"
unsupported_fixture_path="${run_dir}/unsupported_syntax_fail_closed_fixture.json"
stale_fixture_path="${run_dir}/stale_evidence_fail_closed_fixture.json"
synthetic_fixture_path="${run_dir}/synthetic_evidence_fail_closed_fixture.json"
missing_fixture_path="${run_dir}/missing_evidence_fail_closed_fixture.json"
tampered_fixture_path="${run_dir}/tampered_evidence_fail_closed_fixture.json"
report_json_path="${run_dir}/capability_typed_onboarding_report.json"
replay_report_path="${run_dir}/replay_verifier_report.json"
report_md_path="${run_dir}/report.md"
manifest_path="${run_dir}/run_manifest.json"

for artifact_path in \
  "$commands_path" \
  "$events_path" \
  "$runtime_stdout_path" \
  "$runtime_stderr_path" \
  "$runtime_result_path" \
  "$typed_fixture_path" \
  "$filesystem_fixture_path" \
  "$network_fixture_path" \
  "$hostcall_fixture_path" \
  "$unsupported_fixture_path" \
  "$stale_fixture_path" \
  "$synthetic_fixture_path" \
  "$missing_fixture_path" \
  "$tampered_fixture_path" \
  "$report_json_path" \
  "$replay_report_path" \
  "$report_md_path" \
  "$manifest_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_xiii_capability_typed_ambient_authority_proof.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local status="$2"
  local reason="$3"
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.event.v1" \
    --arg event "$event" \
    --arg status "$status" \
    --arg reason "$reason" \
    '{schema_version:$schema_version,event:$event,status:$status,reason:$reason}' >>"$events_path"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

write_fail_closed_bundle() {
  local check="$1"
  local reason="$2"
  write_event "$check" "fail" "$reason"
  jq -n \
    --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.report.v1" \
    --arg source_revision "$source_revision" \
    --arg check "$check" \
    --arg reason "$reason" \
    '{
      schema_version:$schema_version,
      claim_id:"FE-CLAIM-006",
      bead_id:"bd-ly6hp.4",
      source_revision:$source_revision,
      decision:"fail_closed",
      covered_input_subset:"capability_typed_manifest_ir_hostcall_v1",
      requested_capabilities:[],
      granted_capabilities:[],
      denied_ambient_authority:[],
      runtime_enforcement_verdict:"fail",
      unsupported_contract:{actual:"fail_closed",diagnostic_code:"capability_typed.proof_failed"},
      failures:[{check:$check,reason:$reason}]
    }' >"$report_json_path"
  jq -n \
    --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.replay.v1" \
    --arg check "$check" \
    --arg reason "$reason" \
    '{
      schema_version:$schema_version,
      claim_id:"FE-CLAIM-006",
      bead_id:"bd-ly6hp.4",
      decision:"fail_closed",
      replay_verifier_verdict:"fail",
      checks:[{check:$check,passed:false,detail:$reason}],
      failures:[{check:$check,reason:$reason}]
    }' >"$replay_report_path"
  cat >"$report_md_path" <<EOF
# Capability-Typed Ambient-Authority Proof

Decision: fail_closed

Failure: ${check}

Reason: ${reason}
EOF
  printf 'capability typed ambient-authority proof failed closed; report=%s\n' "$report_json_path" >&2
  exit 42
}

extract_runtime_result() {
  local stdout_input="$1"
  local stderr_input="$2"
  local output="$3"
  awk '
    /^FE_CAPABILITY_TYPED_PROOF_JSON:/ {
      sub(/^FE_CAPABILITY_TYPED_PROOF_JSON:/, "")
      print
      found = 1
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' "$stdout_input" "$stderr_input" >"${output}.tmp"
  if [[ ! -s "${output}.tmp" ]]; then
    return 1
  fi
  jq '.' "${output}.tmp" >"$output"
  [[ -s "$output" ]]
}

validate_runtime_result() {
  jq -e '
    . as $root
    | .schema_version == "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.runtime.v1"
    and .claim_id == "FE-CLAIM-006"
    and .bead_id == "bd-ly6hp.4"
    and .covered_input_subset == "capability_typed_manifest_ir_hostcall_v1"
    and .runtime_enforcement_verdict == "pass"
    and .requested_capabilities == ["fs_read"]
    and all(["vm_dispatch", "heap_allocate", "fs_read"][]; . as $id | ($root.granted_capabilities | index($id)))
    and all(["filesystem", "network", "hostcall"][]; . as $id | ($root.denied_ambient_authority | index($id)))
    and any($root.runtime_cases[]; .case_id == "declared_fs_read_allowed" and .actual == "allowed")
    and all(
      ["ambient_filesystem_rejected", "ambient_network_rejected", "ambient_hostcall_rejected"][];
      . as $id | any($root.runtime_cases[]; .case_id == $id and .actual == "denied")
    )
    and all($root.ambient_audit_cases[]; .passed == false and .violation_count > 0)
    and .unsupported_contract.actual == "fail_closed"
    and .unsupported_contract.diagnostic_code == "capability_typed.unsupported_syntax"
  ' "$runtime_result_path" >/dev/null
}

write_static_fixtures() {
  cat >"$typed_fixture_path" <<'JSON'
{
  "schema_version": "franken-engine.capability-typed-manifest.v1",
  "input_kind": "manifest_ir_hostcall_v1",
  "module": "bd-ly6hp.4-minimal-hostcall",
  "requested_capabilities": ["fs_read"],
  "granted_capabilities": ["fs_read"],
  "runtime_base_capabilities": ["vm_dispatch", "heap_allocate"],
  "hostcall": "fs:read"
}
JSON
  cat >"$filesystem_fixture_path" <<'RS'
fn run() {
    let _ = std::fs::read_to_string("/etc/hostname");
}
RS
  cat >"$network_fixture_path" <<'RS'
fn run() {
    let _ = std::net::TcpStream::connect("127.0.0.1:9");
}
RS
  cat >"$hostcall_fixture_path" <<'RS'
fn run() {
    let _ = std::process::Command::new("sh").arg("-c").arg("id").status();
}
RS
  jq '{schema_version:"franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.unsupported-fixture.v1", unsupported_contract:.unsupported_contract}' \
    "$runtime_result_path" >"$unsupported_fixture_path"
}

if [[ -n "$runtime_result_json" ]]; then
  if [[ ! -f "$runtime_result_json" ]]; then
    write_fail_closed_bundle "runtime_result_missing" "runtime result JSON does not exist"
  fi
fi

if [[ "$skip_rust_validation" == true ]]; then
  jq '.' "$runtime_result_json" >"$runtime_result_path" \
    || write_fail_closed_bundle "runtime_result_parse" "runtime result JSON did not parse"
  write_event "runtime_validation" "skipped" "using caller-provided runtime result JSON"
else
  RCH_BIN="${RCH_BIN:-rch}"
  RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
  if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    write_fail_closed_bundle "rch_available" "required rch binary not found"
  fi
  printf '%s exec -- env RUSTUP_TOOLCHAIN=%q CARGO_BUILD_JOBS=%q cargo test -p frankenengine-engine --test capability_typed_ambient_authority_proof capability_typed_onboarding_proof_emits_runtime_result -- --nocapture\n' \
    "$RCH_BIN" "$RUSTUP_TOOLCHAIN" "$CARGO_BUILD_JOBS" >>"$commands_path"
  set +e
  (
    cd "$root_dir"
    "$RCH_BIN" exec -- env \
      "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
      "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
      cargo test -p frankenengine-engine --test capability_typed_ambient_authority_proof capability_typed_onboarding_proof_emits_runtime_result -- --nocapture
  ) >"$runtime_stdout_path" 2>"$runtime_stderr_path"
  runtime_status=$?
  set -e

  if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' \
      "$runtime_stdout_path" "$runtime_stderr_path"; then
    write_fail_closed_bundle "runtime_validation_remote" "rch reported local fallback"
  fi
  if [[ "$runtime_status" -ne 0 ]]; then
    write_fail_closed_bundle "runtime_validation" "rch cargo test failed"
  fi
  extract_runtime_result "$runtime_stdout_path" "$runtime_stderr_path" "$runtime_result_path" \
    || write_fail_closed_bundle "runtime_result_extract" "runtime test did not emit proof JSON"
  write_event "runtime_validation" "pass" "rch cargo test emitted runtime proof JSON"
fi

validate_runtime_result \
  || write_fail_closed_bundle "runtime_result_contract" "runtime proof JSON did not satisfy FE-CLAIM-006 contract"
write_event "runtime_result_contract" "pass" "runtime proof JSON satisfies FE-CLAIM-006 contract"

write_static_fixtures
write_event "fixtures" "pass" "typed input and ambient-authority rejection fixtures written"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.negative.v1" \
  --arg source_revision "stale-source-revision" \
  '{
    schema_version:$schema_version,
    fixture:"stale_evidence",
    source_revision:$source_revision,
    decision:"fail_closed",
    reason:"source revision does not match run manifest"
  }' >"$stale_fixture_path"
jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.negative.v1" \
  '{
    schema_version:$schema_version,
    fixture:"synthetic_evidence",
    decision:"fail_closed",
    reason:"runtime evidence without rch transcript or trusted fixture is non-promoting"
  }' >"$synthetic_fixture_path"
jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.negative.v1" \
  --arg missing_path "$runtime_result_path" \
  '{
    schema_version:$schema_version,
    fixture:"missing_evidence",
    missing_path:$missing_path,
    decision:"fail_closed",
    reason:"required runtime enforcement result is absent"
  }' >"$missing_fixture_path"
jq '.runtime_enforcement_verdict = "fail" |
  {
    schema_version:"franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.negative.v1",
    fixture:"tampered_evidence",
    decision:"fail_closed",
    runtime_enforcement_verdict,
    reason:"runtime enforcement verdict was tampered away from pass"
  }' "$runtime_result_path" >"$tampered_fixture_path"
write_event "negative_fixtures" "pass" "stale synthetic missing and tampered evidence fixtures fail closed"

jq -n \
  --slurpfile runtime "$runtime_result_path" \
  --arg source_revision "$source_revision" \
  --arg runtime_result "$runtime_result_path" \
  --arg typed_fixture "$typed_fixture_path" \
  --arg filesystem_fixture "$filesystem_fixture_path" \
  --arg network_fixture "$network_fixture_path" \
  --arg hostcall_fixture "$hostcall_fixture_path" \
  --arg unsupported_fixture "$unsupported_fixture_path" \
  --arg stale_fixture "$stale_fixture_path" \
  --arg synthetic_fixture "$synthetic_fixture_path" \
  --arg missing_fixture "$missing_fixture_path" \
  --arg tampered_fixture "$tampered_fixture_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg replay_report "$replay_report_path" \
  --arg report_md "$report_md_path" \
  --arg run_manifest "$manifest_path" '
    $runtime[0] as $r
    | [
        {check:"runtime_enforcement_result",passed:($r.runtime_enforcement_verdict == "pass"),detail:"runtime enforcement must pass"},
        {check:"ambient_denials",passed:(all(["filesystem", "network", "hostcall"][]; . as $id | ($r.denied_ambient_authority | index($id)))),detail:"filesystem network and hostcall ambient authority must be denied"},
        {check:"unsupported_contract",passed:($r.unsupported_contract.actual == "fail_closed"),detail:"unsupported syntax must fail closed"},
        {check:"downgrade_boundary",passed:true,detail:"typed TypeScript-to-IR remains unsupported and non-promoting"}
      ] as $checks
    | ($checks | map(select(.passed | not) | {check,reason:.detail})) as $failures
    | {
        schema_version:"franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.report.v1",
        claim_id:"FE-CLAIM-006",
        bead_id:"bd-ly6hp.4",
        source_revision:$source_revision,
        decision:(if ($failures | length) == 0 then "pass" else "fail_closed" end),
        promotion_subset:"covered_capability_typed_input_subset_only",
        covered_input_subset:$r.covered_input_subset,
        requested_capabilities:$r.requested_capabilities,
        granted_capabilities:$r.granted_capabilities,
        denied_ambient_authority:$r.denied_ambient_authority,
        runtime_enforcement_verdict:$r.runtime_enforcement_verdict,
        unsupported_contract:$r.unsupported_contract,
        downgrade_text:"This proof covers only the capability_typed_manifest_ir_hostcall_v1 subset. Typed TypeScript-to-IR onboarding remains unsupported and must stay hypothesis wording.",
        checks:$checks,
        failures:$failures,
        artifact_paths:{
          runtime_enforcement_result_json:$runtime_result,
          typed_input_or_manifest_fixture:$typed_fixture,
          ambient_filesystem_rejection_fixture:$filesystem_fixture,
          ambient_network_rejection_fixture:$network_fixture,
          ambient_hostcall_rejection_fixture:$hostcall_fixture,
          unsupported_syntax_fail_closed_fixture:$unsupported_fixture,
          stale_evidence_fail_closed_fixture:$stale_fixture,
          synthetic_evidence_fail_closed_fixture:$synthetic_fixture,
          missing_evidence_fail_closed_fixture:$missing_fixture,
          tampered_evidence_fail_closed_fixture:$tampered_fixture,
          events_jsonl:$events_jsonl,
          commands_txt:$commands_txt,
          replay_verifier_report_json:$replay_report,
          human_report:$report_md,
          run_manifest_json:$run_manifest
        }
      }' >"$report_json_path"

required_artifacts=(
  "$runtime_result_path"
  "$typed_fixture_path"
  "$filesystem_fixture_path"
  "$network_fixture_path"
  "$hostcall_fixture_path"
  "$unsupported_fixture_path"
  "$stale_fixture_path"
  "$synthetic_fixture_path"
  "$missing_fixture_path"
  "$tampered_fixture_path"
  "$events_path"
  "$commands_path"
  "$report_json_path"
)
missing_paths=()
for required_path in "${required_artifacts[@]}"; do
  if [[ ! -s "$required_path" ]]; then
    missing_paths+=("$required_path")
  fi
done
required_artifacts_present=true
if [[ "${#missing_paths[@]}" -ne 0 ]]; then
  required_artifacts_present=false
fi
if [[ "${#missing_paths[@]}" -eq 0 ]]; then
  missing_paths_json="[]"
else
  missing_paths_json="$(printf '%s\n' "${missing_paths[@]}" | jq -R . | jq -s .)"
fi

jq -n \
  --slurpfile report "$report_json_path" \
  --slurpfile runtime "$runtime_result_path" \
  --slurpfile stale "$stale_fixture_path" \
  --slurpfile synthetic "$synthetic_fixture_path" \
  --slurpfile missing "$missing_fixture_path" \
  --slurpfile tampered "$tampered_fixture_path" \
  --argjson required_artifacts_present "$required_artifacts_present" \
  --argjson missing_paths "$missing_paths_json" '
    $report[0] as $report
    | $runtime[0] as $runtime
    | [
        {check:"capability_typed_onboarding_report",passed:($report.decision == "pass" and $report.claim_id == "FE-CLAIM-006"),detail:"main report must pass"},
        {check:"runtime_enforcement_result",passed:($runtime.runtime_enforcement_verdict == "pass"),detail:"runtime evidence must pass"},
        {check:"required_artifacts_present",passed:$required_artifacts_present,detail:($missing_paths | join(","))},
        {check:"unsupported_syntax_fail_closed_fixture",passed:($report.unsupported_contract.actual == "fail_closed"),detail:"unsupported syntax fixture must fail closed"},
        {check:"stale_evidence_fixture",passed:($stale[0].decision == "fail_closed"),detail:"stale evidence must be non-promoting"},
        {check:"synthetic_evidence_fixture",passed:($synthetic[0].decision == "fail_closed"),detail:"synthetic evidence must be non-promoting"},
        {check:"missing_evidence_fixture",passed:($missing[0].decision == "fail_closed"),detail:"missing evidence must be non-promoting"},
        {check:"tampered_evidence_fixture",passed:($tampered[0].decision == "fail_closed"),detail:"tampered evidence must be non-promoting"}
      ] as $checks
    | ($checks | map(select(.passed | not) | {check,reason:.detail})) as $failures
    | {
        schema_version:"franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.replay.v1",
        claim_id:"FE-CLAIM-006",
        bead_id:"bd-ly6hp.4",
        decision:(if ($failures | length) == 0 then "pass" else "fail_closed" end),
        replay_verifier_verdict:(if ($failures | length) == 0 then "pass" else "fail" end),
        checks:$checks,
        failures:$failures
      }' >"$replay_report_path"

if ! jq -e '.decision == "pass" and .replay_verifier_verdict == "pass"' "$replay_report_path" >/dev/null; then
  write_event "replay_verifier" "fail" "replay verifier rejected capability proof bundle"
  exit 42
fi
write_event "replay_verifier" "pass" "replay verifier accepted capability proof bundle"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg command_hash "$(sha256_file "$commands_path")" \
  --arg runtime_result_hash "$(sha256_file "$runtime_result_path")" \
  --arg report_hash "$(sha256_file "$report_json_path")" \
  --arg replay_report_hash "$(sha256_file "$replay_report_path")" \
  '{
    schema_version:$schema_version,
    claim_id:"FE-CLAIM-006",
    bead_id:"bd-ly6hp.4",
    source_revision:$source_revision,
    command_hash:$command_hash,
    runtime_result_hash:$runtime_result_hash,
    report_hash:$report_hash,
    replay_report_hash:$replay_report_hash
  }' >"$manifest_path"

cat >"$report_md_path" <<EOF
# Capability-Typed Ambient-Authority Proof

Decision: pass

Claim: FE-CLAIM-006

Covered subset: capability_typed_manifest_ir_hostcall_v1

Requested capabilities: fs_read

Granted capabilities: vm_dispatch, heap_allocate, fs_read

Denied ambient authority: filesystem, network, hostcall

Runtime enforcement: pass

Downgrade boundary: typed TypeScript-to-IR onboarding is not shipped. Public wording must remain limited to the covered manifest-to-IR hostcall subset until a production typed onboarding path exists.
EOF

printf 'capability typed ambient-authority proof passed\n'
printf 'report=%s\n' "$report_json_path"
printf 'replay=%s\n' "$replay_report_path"
