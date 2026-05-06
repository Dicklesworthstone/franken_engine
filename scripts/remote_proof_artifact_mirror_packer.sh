#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_ARTIFACT_MIRROR_PACKER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-artifact-mirror-packer}"
run_id="${REMOTE_PROOF_ARTIFACT_MIRROR_PACKER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_ARTIFACT_MIRROR_PACKER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

bundle_report_json=""
artifact_files_json=""
retrieval_request_json=""
retrieved_files_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_artifact_mirror_packer.sh --bundle-report-json FILE --artifact-files-json FILE --retrieval-request-json FILE --retrieved-files-json FILE [OPTIONS]

Build a content-addressed mirror manifest and minimal retrieval pack for a
resident remote proof bundle, then verify the retrieved file set against that
pack. This checker is deterministic and fixture-driven; it does not fetch files
from workers or run proof commands.

Required:
  --bundle-report-json FILE
  --artifact-files-json FILE
  --retrieval-request-json FILE
  --retrieved-files-json FILE

Optional:
  --output-dir DIR

Artifacts:
  artifact_mirror_manifest.json
  retrieval_pack.json
  retrieval_verification_report.json
  commands.txt
  events.jsonl
  report.md

Exit codes:
  0  mirror, pack, and retrieved files are coherent
  42 fail-closed due to collision, missing artifact, broad retrieval, or drift
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-report-json)
      bundle_report_json="${2:-}"
      shift 2
      ;;
    --artifact-files-json)
      artifact_files_json="${2:-}"
      shift 2
      ;;
    --retrieval-request-json)
      retrieval_request_json="${2:-}"
      shift 2
      ;;
    --retrieved-files-json)
      retrieved_files_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$bundle_report_json" || -z "$artifact_files_json" || -z "$retrieval_request_json" || -z "$retrieved_files_json" ]]; then
  printf 'artifact mirror packer requires --bundle-report-json, --artifact-files-json, --retrieval-request-json, and --retrieved-files-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof artifact mirror packing\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof artifact mirror packing\n' >&2
  exit 2
fi

json_input() {
  local path="$1"
  local label="$2"

  if [[ ! -f "$path" ]]; then
    printf 'artifact mirror packer missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'artifact mirror packer invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

json_input "$bundle_report_json" "bundle report"
json_input "$artifact_files_json" "artifact files"
json_input "$retrieval_request_json" "retrieval request"
json_input "$retrieved_files_json" "retrieved files"

mkdir -p "$run_dir"
mirror_manifest_path="${run_dir}/artifact_mirror_manifest.json"
mirror_manifest_tmp="${mirror_manifest_path}.tmp"
retrieval_pack_path="${run_dir}/retrieval_pack.json"
retrieval_pack_tmp="${retrieval_pack_path}.tmp"
verification_report_path="${run_dir}/retrieval_verification_report.json"
verification_report_tmp="${verification_report_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
bundle_normalized="${run_dir}/bundle_report.normalized.json"
artifacts_normalized="${run_dir}/artifact_files.normalized.json"
request_normalized="${run_dir}/retrieval_request.normalized.json"
retrieved_normalized="${run_dir}/retrieved_files.normalized.json"
report_core="${run_dir}/retrieval_verification_core.json"
: >"$events_path"

printf './scripts/remote_proof_artifact_mirror_packer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    bundle_id: (.bundle_id // .suite_id // "unknown"),
    bundle_decision: (.bundle_decision // .status // "unknown"),
    expected_worker_id: (.expected_worker_id // .worker_id // null),
    expected_target_dir: (.expected_target_dir // .target_dir // null),
    artifact_surface: (
      [
        ((.artifact_paths // {}) | to_entries[]? | select((.value | type) == "string") | .value),
        ((.phase_results // [])[]? | .stdout_log? // empty),
        ((.phase_results // [])[]? | .stderr_log? // empty)
      ]
      | map(tostring)
      | unique
      | sort
    )
  }
' "$bundle_report_json" >"$bundle_normalized"
write_event "bundle_report_loaded" "normalized resident bundle report"

jq -cS '
  def role_list($artifact):
    (
      if (($artifact.roles? // null) | type) == "array" then
        $artifact.roles
      elif (($artifact.role? // null) | type) == "string" then
        [$artifact.role]
      else
        []
      end
    )
    | map(tostring)
    | unique
    | sort;
  def normalized_artifact($artifact):
    (role_list($artifact)) as $roles
    | ($artifact.path // $artifact.logical_path // $artifact.artifact_path // "") as $path
    | ($artifact.sha256 // $artifact.content_hash // $artifact.digest // "") as $sha
    | {
        path: ($path | tostring),
        size_bytes: ($artifact.size_bytes // 0),
        roles: $roles,
        replay_critical: ($artifact.replay_critical // ($roles | index("replay") != null)),
        sha256: ($sha | tostring | ascii_downcase),
        content_address: ("sha256:" + ($sha | tostring | ascii_downcase))
      };
  {
    schema_version: (.schema_version // "unknown"),
    artifacts: (
      if type == "array" then . else (.artifacts // .files // []) end
      | if type == "array" then . else [] end
      | map(normalized_artifact(.))
      | sort_by(.path, .content_address)
    )
  }
' "$artifact_files_json" >"$artifacts_normalized"
write_event "artifact_files_loaded" "normalized content-addressed artifact file list"

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    requested_roles: (
      (.requested_roles // .roles // ["replay"])
      | if type == "array" then map(tostring) else ["replay"] end
      | unique
      | sort
    )
  }
' "$retrieval_request_json" >"$request_normalized"
write_event "retrieval_request_loaded" "normalized retrieval request"

jq -cS '
  {
    retrieved_artifacts: (
      if type == "array" then
        map(tostring)
      else
        (.retrieved_artifacts // .paths // [])
        | if type == "array" then map(tostring) else [] end
      end
      | unique
      | sort
    )
  }
' "$retrieved_files_json" >"$retrieved_normalized"
write_event "retrieved_files_loaded" "normalized retrieved artifact path set"

jq -n \
  --slurpfile bundle "$bundle_normalized" \
  --slurpfile artifacts "$artifacts_normalized" \
  --slurpfile request "$request_normalized" \
  --slurpfile retrieved "$retrieved_normalized" '
  def broad_path($path):
    ($path | test("(^|/)(target|\\.rch-target|rch_target|tmp/rch_target)($|/|\\*)"))
    or ($path | test("/\\*\\*$"))
    or ($path | test("(^|/)[*]$"));
  def intersects($a; $b):
    (($a // []) as $left | ($b // []) as $right | (($left - ($left - $right)) | length) > 0);
  ($bundle[0]) as $bundle
  | ($artifacts[0].artifacts // []) as $artifacts
  | ($request[0].requested_roles // ["replay"]) as $requested_roles
  | ($retrieved[0].retrieved_artifacts // []) as $retrieved_paths
  | ($bundle.artifact_surface // []) as $bundle_surface
  | (
      $artifacts
      | map(select((.path | length) == 0 or (.sha256 | test("^[a-f0-9]{64}$") | not)))
    ) as $invalid_artifacts
  | (
      $artifacts
      | group_by(.content_address)
      | map(select(length > 1))
      | map({
          content_address: .[0].content_address,
          paths: (map(.path) | unique | sort)
        })
      | map(select((.paths | length) > 1))
    ) as $content_address_collisions
  | (
      $artifacts
      | map(select(.path as $path | ($bundle_surface | length) > 0 and (($bundle_surface | index($path)) == null)))
      | map(.path)
      | unique
      | sort
    ) as $not_in_bundle_surface
  | (
      $artifacts
      | map(select(intersects(.roles; $requested_roles) or (.replay_critical == true)))
      | sort_by(.path, .content_address)
    ) as $selected_artifacts
  | ($selected_artifacts | map(.path) | unique | sort) as $selected_paths
  | ($selected_artifacts | map(select(.replay_critical == true) | .path) | unique | sort) as $critical_paths
  | (($selected_paths | map(select(broad_path(.)))) | unique | sort) as $broad_selected
  | (($retrieved_paths | map(select(broad_path(.)))) | unique | sort) as $broad_retrieved
  | (($selected_paths - $retrieved_paths) | unique | sort) as $missing_selected
  | (($critical_paths - $retrieved_paths) | unique | sort) as $missing_critical
  | (($retrieved_paths - $selected_paths) | unique | sort) as $undeclared_retrieved
  | (
      if (($invalid_artifacts | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "artifact metadata is missing a path or valid sha256 content address",
          exit_code: 42
        }
      elif (($content_address_collisions | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "duplicate content-address collision maps multiple logical paths",
          exit_code: 42
        }
      elif (($not_in_bundle_surface | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "artifact manifest includes paths absent from the bundle artifact surface",
          exit_code: 42
        }
      elif (($broad_selected | length) > 0) or (($broad_retrieved | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "retrieval pack includes broad target-dir or wildcard paths",
          exit_code: 42
        }
      elif (($missing_critical | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "replay-critical artifact is missing from retrieved pack",
          exit_code: 42
        }
      elif (($missing_selected | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "retrieved pack is missing selected artifacts",
          exit_code: 42
        }
      elif (($undeclared_retrieved | length) > 0) then
        {
          verification_decision: "fail_closed",
          reason: "retrieved pack contains undeclared files",
          exit_code: 42
        }
      else
        {
          verification_decision: "pass",
          reason: "retrieved pack matches the minimal content-addressed artifact set",
          exit_code: 0
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.remote-proof-artifact-mirror-verification.v1",
      bundle_id: ($bundle.bundle_id // "unknown"),
      bundle_decision: ($bundle.bundle_decision // "unknown"),
      requested_roles: $requested_roles,
      mirror_artifacts: $artifacts,
      retrieval_pack_artifacts: $selected_artifacts,
      retrieved_artifacts: $retrieved_paths,
      invalid_artifacts: $invalid_artifacts,
      content_address_collisions: $content_address_collisions,
      artifacts_absent_from_bundle_surface: $not_in_bundle_surface,
      broad_selected_artifacts: $broad_selected,
      broad_retrieved_artifacts: $broad_retrieved,
      missing_selected_artifacts: $missing_selected,
      missing_replay_critical_artifacts: $missing_critical,
      undeclared_retrieved_artifacts: $undeclared_retrieved,
      verification_decision: $decision.verification_decision,
      reason: $decision.reason,
      exit_code: $decision.exit_code
    }
' >"$report_core"

input_hash="$(
  jq -n \
    --slurpfile bundle "$bundle_normalized" \
    --slurpfile artifacts "$artifacts_normalized" \
    --slurpfile request "$request_normalized" \
    --slurpfile retrieved "$retrieved_normalized" '
      {
        bundle_report: ($bundle[0]),
        artifacts: ($artifacts[0]),
        retrieval_request: ($request[0]),
        retrieved_files: ($retrieved[0])
      }
    ' | jq -cS . | sha256sum | awk '{print $1}'
)"
verification_hash="$(jq -cS . "$report_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg verification_hash "$verification_hash" \
  --arg mirror_manifest_path "$mirror_manifest_path" \
  --arg retrieval_pack_path "$retrieval_pack_path" \
  --arg verification_report_path "$verification_report_path" \
  --arg summary_path "$summary_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      verification_hash: $verification_hash
    },
    artifact_paths: {
      artifact_mirror_manifest_json: $mirror_manifest_path,
      retrieval_pack_json: $retrieval_pack_path,
      retrieval_verification_report_json: $verification_report_path,
      report_md: $summary_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
' "$report_core" >"$verification_report_tmp"
mv "$verification_report_tmp" "$verification_report_path"

jq -n \
  --slurpfile report "$verification_report_path" '
  {
    schema_version: "franken-engine.remote-proof-artifact-mirror-manifest.v1",
    bundle_id: $report[0].bundle_id,
    bundle_decision: $report[0].bundle_decision,
    artifacts: $report[0].mirror_artifacts,
    content_address_collisions: $report[0].content_address_collisions,
    hash_basis: $report[0].hash_basis,
    artifact_paths: $report[0].artifact_paths
  }' >"$mirror_manifest_tmp"
mv "$mirror_manifest_tmp" "$mirror_manifest_path"

jq -n \
  --slurpfile report "$verification_report_path" '
  {
    schema_version: "franken-engine.remote-proof-retrieval-pack.v1",
    bundle_id: $report[0].bundle_id,
    requested_roles: $report[0].requested_roles,
    selected_artifacts: $report[0].retrieval_pack_artifacts,
    selected_paths: ($report[0].retrieval_pack_artifacts | map(.path) | unique | sort),
    replay_critical_paths: ($report[0].retrieval_pack_artifacts | map(select(.replay_critical == true) | .path) | unique | sort),
    hash_basis: $report[0].hash_basis,
    artifact_paths: $report[0].artifact_paths
  }' >"$retrieval_pack_tmp"
mv "$retrieval_pack_tmp" "$retrieval_pack_path"

{
  printf '# Remote Proof Artifact Mirror Packer\n\n'
  printf -- '- Decision: %s\n' "$(jq -r '.verification_decision' "$verification_report_path")"
  printf -- '- Reason: %s\n' "$(jq -r '.reason' "$verification_report_path")"
  printf -- '- Bundle ID: %s\n' "$(jq -r '.bundle_id' "$verification_report_path")"
  printf -- '- Mirror artifacts: %s\n' "$(jq -r '.mirror_artifacts | length' "$verification_report_path")"
  printf -- '- Selected artifacts: %s\n' "$(jq -r '.retrieval_pack_artifacts | length' "$verification_report_path")"
  printf -- '- Retrieved artifacts: %s\n' "$(jq -r '.retrieved_artifacts | length' "$verification_report_path")"
  printf -- "- Input hash: \`%s\`\n" "$(jq -r '.hash_basis.input_hash' "$verification_report_path")"
  printf -- "- Verification hash: \`%s\`\n" "$(jq -r '.hash_basis.verification_hash' "$verification_report_path")"
  printf '\n## Diagnostics\n\n'
  jq -r '
    [
      "| Field | Count |",
      "| --- | ---: |",
      "| invalid_artifacts | \(.invalid_artifacts | length) |",
      "| content_address_collisions | \(.content_address_collisions | length) |",
      "| artifacts_absent_from_bundle_surface | \(.artifacts_absent_from_bundle_surface | length) |",
      "| broad_selected_artifacts | \(.broad_selected_artifacts | length) |",
      "| broad_retrieved_artifacts | \(.broad_retrieved_artifacts | length) |",
      "| missing_selected_artifacts | \(.missing_selected_artifacts | length) |",
      "| missing_replay_critical_artifacts | \(.missing_replay_critical_artifacts | length) |",
      "| undeclared_retrieved_artifacts | \(.undeclared_retrieved_artifacts | length) |"
    ] | join("\n")
  ' "$verification_report_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

write_event "artifact_mirror_verification_written" "wrote mirror manifest, retrieval pack, and verification report"

printf 'remote_proof_artifact_mirror_manifest=%s\n' "$mirror_manifest_path"
printf 'remote_proof_retrieval_pack=%s\n' "$retrieval_pack_path"
printf 'remote_proof_retrieval_verification=%s\n' "$verification_report_path"

exit "$(jq -r '.exit_code' "$verification_report_path")"
