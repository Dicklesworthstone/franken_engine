#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_FEEDBACK_CONTRACT_PROFILE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-feedback-contract-profile}"
run_id="${SWARM_FEEDBACK_CONTRACT_PROFILE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_FEEDBACK_CONTRACT_PROFILE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_FEEDBACK_CONTRACT_PROFILE_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_feedback_contract_profile.sh --input-json FILE [OPTIONS]

Builds a read-only advisory artifact/profile contract for the bd-gvhsx
feedback-loop family. The command consumes saved JSON only; it never queries
live Agent Mail, runs Cargo/rch, mutates beads, or schedules work.

Required:
  --input-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_feedback_contract_profile.json
  profile_field_inventory.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   contract profile emitted with pass decision
  42  stale, missing, contradictory, or unsafe advisory evidence forced fail_closed
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$input_json" ]]; then
  printf 'missing required --input-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm feedback contract profile\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm feedback contract profile\n' >&2
  exit 2
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
contract_path="${run_dir}/swarm_feedback_contract_profile.json"
inventory_path="${run_dir}/profile_field_inventory.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"
contract_tmp="${contract_path}.tmp"

for artifact_path in \
  "$contract_path" \
  "$inventory_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$normalized_input" \
  "$contract_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/swarm_feedback_contract_profile.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg contract_path "$contract_path" \
  --arg inventory_path "$inventory_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def src: $input[0];
  def authorities: (src.authorities // []);
  def profiles: (src.profiles // []);
  def authority($id): [authorities[] | select((.authority_id // "") == $id)][0] // null;
  def authority_present($id): ((authority($id) // {}) | (.present // false) == true);
  def failure($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def profile_policy_missing($profile):
    (($profile.proof_state_wording // "") | test("observed|proof-state|proof state|downgrade") | not)
    or (($profile.mutation_policy // "") != "advisory_only");

  (
    []
    + (if authority_present("bd-eozx0") then [] else [
        failure("missing_upstream_live_state"; "bd-eozx0";
          "canonical live-state authority is missing or not marked present";
          "Provide the bd-eozx0 live-state contract/profile snapshot before implementation.")
      ] end)
    + (if authority_present("bd-x82vp") then [] else [
        failure("missing_resource_authority"; "bd-x82vp";
          "resource lease/admission authority is missing or not marked present";
          "Provide the bd-x82vp resource authority snapshot before implementation.")
      ] end)
    + ([authorities[]
        | select((.present // false) == true)
        | select((.freshness.status // "fresh") != "fresh")
        | failure("stale_proof_state_evidence"; (.authority_id // "unknown_authority");
            ("authority freshness is " + (.freshness.status // "unknown"));
            "Refresh the saved evidence or downgrade the downstream recommendation.")])
    + ([(src.contradictions // [])[]
        | failure("contradictory_advisory_input"; (.source_id // "contradiction");
            (.detail // "contradictory advisory evidence");
            (.remediation // "Resolve contradictory snapshots before treating the profile as actionable."))])
    + ([profiles[]
        | select(profile_policy_missing(.))
        | failure("missing_profile_policy"; (.profile_id // "unknown_profile");
            "profile lacks observed/proof-state wording or advisory_only mutation policy";
            "Add proof-state wording and explicit advisory_only mutation policy.")])
  ) as $failures
  | {
      schema_version: "franken-engine.swarm-feedback-contract-profile.report.v1",
      component: "swarm_feedback_contract_profile",
      source_revision: $source_revision,
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      decision: (if ($failures | length) == 0 then "pass" else "fail_closed" end),
      fail_closed_reasons: $failures,
      closed_authority_ids: ["bd-eozx0", "bd-x82vp"],
      authority_status: [
        authorities[]
        | {
            authority_id,
            present: (.present // false),
            artifact: (.artifact // null),
            freshness_status: (.freshness.status // "unknown"),
            required_fields: (.required_fields // [])
          }
      ],
      profiles: [
        profiles[]
        | {
            profile_id,
            output_artifact,
            input_authorities: (.input_authorities // []),
            fields: (.fields // []),
            freshness_policy,
            proof_state_wording,
            fail_closed_behavior,
            mutation_policy
          }
      ],
      field_inventory: [
        profiles[]
        | {
            profile_id,
            output_artifact,
            input_authorities: ((.input_authorities // []) | sort),
            fields: ((.fields // []) | sort),
            required_authority_fields: [
              (.input_authorities // [])[] as $authority_id
              | (authority($authority_id) // {})
              | {
                  authority_id: $authority_id,
                  required_fields: ((.required_fields // []) | sort)
                }
            ]
          }
      ],
      artifact_paths: {
        contract_profile_json: $contract_path,
        profile_field_inventory_json: $inventory_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        reads_saved_files_only: true,
        queries_live_agent_mail: false,
        mutates_beads: false,
        sends_agent_mail: false,
        runs_cargo: false,
        runs_rch: false,
        schedules_work: false
      }
    }
' >"$contract_tmp"
mv "$contract_tmp" "$contract_path"

jq '.field_inventory' "$contract_path" >"$inventory_path"

jq -c '
  if (.fail_closed_reasons | length) == 0 then
    [{
      schema_version: "franken-engine.swarm-feedback-contract-profile.event.v1",
      component: "swarm_feedback_contract_profile",
      event: "profile_contract_passed",
      outcome: "pass",
      error_code: null,
      source_id: null,
      detail: "contract profile passed"
    }]
  else
    [.fail_closed_reasons[]
      | {
          schema_version: "franken-engine.swarm-feedback-contract-profile.event.v1",
          component: "swarm_feedback_contract_profile",
          event: "fail_closed_reason",
          outcome: "fail_closed",
          error_code: .code,
          source_id: .source_id,
          detail: .detail
        }]
  end
  | .[]
' "$contract_path" >"$events_path"

jq -r '
  "# Swarm Feedback Contract Profile",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Source revision: `" + .source_revision + "`"),
  ("- Input SHA-256: `" + .input.sha256 + "`"),
  ("- Profiles: `" + (.profiles | length | tostring) + "`"),
  "",
  "## Fail-Closed Reasons",
  "",
  (if (.fail_closed_reasons | length) == 0 then
    "none"
  else
    (.fail_closed_reasons[]
      | "- `" + .code + "` `" + .source_id + "`: " + .detail + " Remediation: " + .remediation)
  end),
  "",
  "## Profiles",
  "",
  (.profiles[]
    | "- `" + .profile_id + "` -> `" + .output_artifact + "`; mutation policy `" + .mutation_policy + "`; proof wording `" + .proof_state_wording + "`")
' "$contract_path" >"$report_path"

printf 'swarm_feedback_contract_profile=%s\n' "$contract_path"
printf 'swarm_feedback_field_inventory=%s\n' "$inventory_path"
printf 'swarm_feedback_contract_events=%s\n' "$events_path"

if jq -e '.decision != "pass"' "$contract_path" >/dev/null; then
  exit 42
fi
exit 0
