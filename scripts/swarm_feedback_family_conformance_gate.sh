#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_FEEDBACK_FAMILY_CONFORMANCE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-feedback-family-conformance}"
run_id="${SWARM_FEEDBACK_FAMILY_CONFORMANCE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_FEEDBACK_FAMILY_CONFORMANCE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_FEEDBACK_FAMILY_CONFORMANCE_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_feedback_family_conformance_gate.sh --input-json FILE [OPTIONS]

Checks saved bd-gvhsx feedback-loop artifact summaries for advisory-only
conformance, required profile coverage, stale upstream evidence, local fallback
contamination, mutation wording, and claim/proof-state downgrade requirements.
It never runs Cargo/rch, mutates live workers, sends Agent Mail, releases
reservations, reopens beads, or promotes documentation claims.

Required:
  --input-json FILE

Options:
  --source-revision REV
  --output-dir DIR

Artifacts:
  family_conformance.json
  golden_comparison.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   conformance report emitted with pass or degraded decision
  42  fail-closed conformance violation found
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
  printf 'jq is required for feedback family conformance gate\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for feedback family conformance gate\n' >&2
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
conformance_path="${run_dir}/family_conformance.json"
golden_path="${run_dir}/golden_comparison.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"
conformance_tmp="${conformance_path}.tmp"

for artifact_path in \
  "$conformance_path" \
  "$golden_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$normalized_input" \
  "$conformance_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/swarm_feedback_family_conformance_gate.sh' >"$commands_path"
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
  --arg conformance_path "$conformance_path" \
  --arg golden_path "$golden_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def src: $input[0];
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def reason($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def required_ids:
    arr(src.required_artifacts // [
      "contract_profile",
      "proof_portfolio",
      "target_dir_heatmap",
      "agent_mail_sla",
      "stalled_ownership_reopen",
      "since_green_diff"
    ]);
  def artifact_rows:
    if (src.artifacts | type) == "array" then src.artifacts
    elif (src.artifacts | type) == "object" then
      [src.artifacts | to_entries[] | (.value + {artifact_id:.key})]
    else [] end;
  def artifact_by_id($id):
    [artifact_rows[] | select((.artifact_id // "") == $id)][0] // null;
  def bool_field($row; $key):
    if ($row | type) != "object" then false
    elif ($row | has($key)) then ($row[$key] == true)
    else false end;
  def disallowed_mutation($row):
    any([
      "runs_cargo",
      "runs_rch",
      "mutates_br",
      "sends_agent_mail",
      "releases_reservations",
      "runs_br_reopen",
      "reassigns_beads",
      "edits_files",
      "mutates_claims",
      "reruns_proofs",
      "promotes_documentation_claims",
      "mutates_live_workers"
    ][]; bool_field($row.non_mutation_attestation // {}; .));
  def reason_codes($row):
    arr($row.fail_closed_reasons // []) + arr($row.degraded_reasons // []);
  def has_reason_code($row; $needle):
    any(reason_codes($row)[]?; (.code // .) == $needle);
  def local_fallback($row):
    (($row.local_fallback_detected // false) == true)
    or has_reason_code($row; "local_rch_fallback_contamination")
    or has_reason_code($row; "local_fallback_in_current");
  def stale_row($row):
    (($row.evidence_freshness // "fresh") != "fresh")
    or has_reason_code($row; "stale_current_bundle")
    or has_reason_code($row; "stale_proof_state_evidence")
    or has_reason_code($row; "stale_upstream_evidence");
  def claim_downgrade($row):
    (($row.claim_downgrade_required // false) == true)
    or (($row.proof_state // "") | IN("hypothesis_without_artifact", "targeted_without_live_proof", "claim_requires_downgrade"))
    or has_reason_code($row; "claim_downgrade_required");
  def artifact_summary:
    [artifact_rows[] as $row
      | {
          artifact_id:($row.artifact_id // "unknown"),
          present:(($row.present // true) == true),
          decision:($row.decision // "unknown"),
          evidence_freshness:($row.evidence_freshness // "fresh"),
          advisory_only:(($row.non_mutation_attestation.advisory_only // true) == true),
          local_fallback_detected:local_fallback($row),
          mutation_violation:(($row.mutation_wording_detected // false) == true or disallowed_mutation($row)),
          claim_downgrade_required:claim_downgrade($row)
        }];

  ([required_ids[] as $id
    | select((artifact_by_id($id) == null) or ((artifact_by_id($id).present // true) != true))
    | reason("missing_required_artifact"; $id;
        "required feedback-loop artifact is missing";
        "Generate the missing child artifact before running family conformance.")
  ]) as $missing_required
  | ([]
    + (if (artifact_by_id("contract_profile") == null) or ((artifact_by_id("contract_profile").decision // "") != "pass") then [
        reason("missing_profile_contract"; "contract_profile";
          "shared advisory profile contract is absent or not passing";
          "Run the bd-gvhsx.6 profile gate before trusting family output.")
      ] else [] end)
    + $missing_required
    + ([artifact_rows[] | select(local_fallback(.))
        | reason("local_fallback_contamination"; (.artifact_id // "unknown");
            "feedback artifact contains local fallback contamination";
            "Discard contaminated evidence and rerun from remote-proof snapshots.")])
    + ([artifact_rows[] | select((.mutation_wording_detected // false) == true or disallowed_mutation(.))
        | reason("mutation_wording"; (.artifact_id // "unknown");
            "artifact claims or permits live mutation in an advisory-only family gate";
            "Rewrite output as manual advisory text and rerun the smoke gate.")])
  ) as $fail_closed_reasons
  | ([]
    + (if ((src.upstream_evidence.live_state_freshness // "fresh") != "fresh") then [
        reason("stale_upstream_evidence"; "bd-eozx0";
          "live-state authority evidence is stale";
          "Refresh the live read-only snapshot bundle before claiming conformance.")
      ] else [] end)
    + ([artifact_rows[] | select(stale_row(.))
        | reason("stale_artifact_evidence"; (.artifact_id // "unknown");
            "feedback artifact uses stale evidence";
            "Refresh or downgrade proof-state wording before relying on the artifact.")])
    + ([artifact_rows[] | select(claim_downgrade(.))
        | reason("claim_proof_state_downgrade_required"; (.artifact_id // "unknown");
            "artifact requires targeted/hypothesis wording rather than observed live claim wording";
            "Downgrade operator-facing claim language to observed proof-state.")
      ])
  ) as $degraded_reasons
  | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
     elif ($degraded_reasons | length) > 0 then "degraded"
     else "pass" end) as $decision
  | {
      schema_version:"franken-engine.swarm-feedback-family-conformance.v1",
      source_revision:$source_revision,
      input_json:$input_json,
      normalized_input:$normalized_input,
      evidence_hash:$input_hash,
      decision:$decision,
      artifact_summary:artifact_summary,
      fail_closed_reasons:$fail_closed_reasons,
      degraded_reasons:$degraded_reasons,
      required_artifacts:required_ids,
      artifact_paths:{
        family_conformance_json:$conformance_path,
        golden_comparison_md:$golden_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      },
      non_mutation_attestation:{
        advisory_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_live_workers:false,
        sends_agent_mail:false,
        releases_reservations:false,
        reopens_beads:false,
        promotes_documentation_claims:false
      }
    }
' >"$conformance_tmp"
mv "$conformance_tmp" "$conformance_path"

jq -r '
  "# Feedback Family Golden Comparison",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Evidence hash: `" + .evidence_hash + "`"),
  "",
  "| Artifact | Present | Decision | Freshness | Local fallback | Mutation violation | Claim downgrade |",
  "| --- | --- | --- | --- | --- | --- | --- |",
  (.artifact_summary[]
    | "| `" + .artifact_id + "` | `" + (.present | tostring) + "` | `" + .decision + "` | `" + .evidence_freshness + "` | `" + (.local_fallback_detected | tostring) + "` | `" + (.mutation_violation | tostring) + "` | `" + (.claim_downgrade_required | tostring) + "` |")
' "$conformance_path" >"$golden_path"

jq -r '
  "# Feedback Family Conformance Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Fail-closed reasons: `" + ((.fail_closed_reasons | length) | tostring) + "`"),
  ("- Degraded reasons: `" + ((.degraded_reasons | length) | tostring) + "`"),
  "",
  "## Reasons",
  "",
  (if ((.fail_closed_reasons + .degraded_reasons) | length) == 0 then
    "none"
  else
    ((.fail_closed_reasons + .degraded_reasons)[]
      | "- `" + .code + "` `" + .source_id + "`: " + .detail)
  end)
' "$conformance_path" >"$report_path"

jq -c '
  ((.fail_closed_reasons[]? | . + {severity:"error"})
    , (.degraded_reasons[]? | . + {severity:"warning"}))
  | {
      schema_version:"franken-engine.swarm-feedback-family-conformance.event.v1",
      component:"swarm_feedback_family_conformance_gate",
      event:"family_conformance_reason",
      severity,
      code,
      source_id
    }
' "$conformance_path" >"$events_path"
if [[ ! -s "$events_path" ]]; then
  jq -nc '{
    schema_version:"franken-engine.swarm-feedback-family-conformance.event.v1",
    component:"swarm_feedback_family_conformance_gate",
    event:"family_conformance_passed",
    severity:"info",
    code:null,
    source_id:null
  }' >"$events_path"
fi

printf 'family_conformance=%s\n' "$conformance_path"
printf 'golden_comparison=%s\n' "$golden_path"
printf 'feedback_family_events=%s\n' "$events_path"

if jq -e '.decision == "fail_closed"' "$conformance_path" >/dev/null; then
  exit 42
fi
exit 0
