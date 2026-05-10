#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${OBJECTIVE_COMPLETION_AUDIT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-objective-completion-audit}"
run_id="${OBJECTIVE_COMPLETION_AUDIT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OBJECTIVE_COMPLETION_AUDIT_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OBJECTIVE_COMPLETION_AUDIT_SOURCE_REVISION:-}"
case_id="manual"
objective_json=""
evidence_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/objective_artifact_completion_audit_gate.sh --objective-json FILE --evidence-json FILE [OPTIONS]

Audits broad operator objectives against concrete artifacts, command receipts,
bead closeout state, and proof receipts. Passing tests or manifests are not
accepted as completion unless they cover the required deliverables.

Required:
  --objective-json FILE     Deliverables and required evidence.
  --evidence-json FILE      Concrete observed evidence.

Options:
  --case-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  completion_audit_report.json
  missing_evidence.jsonl
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   complete audit
  42  incomplete, weak, or deferred audit
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --objective-json)
      objective_json="${2:-}"
      shift 2
      ;;
    --evidence-json)
      evidence_json="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for objective completion audit\n' >&2
  exit 2
fi
if [[ -z "$objective_json" || -z "$evidence_json" ]]; then
  printf 'completion audit requires --objective-json and --evidence-json\n' >&2
  usage
  exit 64
fi
for input_path in "$objective_json" "$evidence_json"; do
  if [[ ! -f "$input_path" ]]; then
    printf 'input JSON not found: %s\n' "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid input JSON: %s\n' "$input_path" >&2
    exit 64
  fi
done
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
objective_normalized="${run_dir}/objective.normalized.json"
evidence_normalized="${run_dir}/evidence.normalized.json"
report_json="${run_dir}/completion_audit_report.json"
report_tmp="${report_json}.tmp"
missing_jsonl="${run_dir}/missing_evidence.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"

for artifact_path in "$objective_normalized" "$evidence_normalized" "$report_json" "$report_tmp" "$missing_jsonl" "$events_path" "$commands_path" "$report_md"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$objective_json" >"$objective_normalized"
jq -cS . "$evidence_json" >"$evidence_normalized"
: >"$events_path"
printf './scripts/objective_artifact_completion_audit_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile objective "$objective_normalized" \
  --slurpfile evidence "$evidence_normalized" \
  --arg schema_version "franken-engine.objective-completion-audit-report.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg objective_normalized "$objective_normalized" \
  --arg evidence_normalized "$evidence_normalized" \
  --arg report_json "$report_json" \
  --arg missing_jsonl "$missing_jsonl" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def low($v): ($v // "" | tostring | ascii_downcase);
  def evidence_rows($name): arr($evidence[0][$name]);
  def deliverables: arr($objective[0].deliverables);
  def artifact_ok($path):
    any(evidence_rows("artifacts")[]?; (.path // "") == $path and (low(.status) | IN("present","changed","committed","generated")));
  def command_ok($id):
    any(evidence_rows("commands")[]?; (.id // .command_id // "") == $id and ((.exit_code // 1) == 0));
  def bead_ok($id):
    any(evidence_rows("beads")[]?; (.id // "") == $id and low(.status) == "closed");
  def proof_ok($id):
    any(evidence_rows("proof_receipts")[]?; (.id // .receipt_id // "") == $id and low(.status) == "passed" and ((.reuse_eligible // true) == true));
  def manifest_covers($id):
    any(evidence_rows("manifests")[]?; arr(.covers) | index($id));
  def memory_only($id):
    any(evidence_rows("memory_notes")[]?; arr(.covers) | index($id));
  def missing($kind; $id; $detail):
    {kind:$kind, id:$id, detail:$detail};
  def audit_one($d):
    ($d.deliverable_id // $d.id // "") as $id
    | ([
        arr($d.required_artifacts)[]? as $path
        | select(artifact_ok($path) | not)
        | missing("artifact"; $path; "required artifact not present in evidence")
      ] + [
        arr($d.required_commands)[]? as $cmd
        | select(command_ok($cmd) | not)
        | missing("command"; $cmd; "required command receipt missing or nonzero")
      ] + [
        arr($d.required_beads)[]? as $bead
        | select(bead_ok($bead) | not)
        | missing("bead"; $bead; "required bead is not closed")
      ] + [
        arr($d.required_proofs)[]? as $proof
        | select(proof_ok($proof) | not)
        | missing("proof"; $proof; "required proof receipt missing, stale, failed, or not reuse-eligible")
      ]) as $missing
    | ([
        if (($missing | length) > 0 and manifest_covers($id)) then
          {code:"FE-IW3-COMPLETION-MANIFEST-PROXY"; detail:"manifest mentions deliverable but concrete required evidence is missing"}
        else empty end,
        if (memory_only($id)) then
          {code:"FE-IW3-COMPLETION-MEMORY-ONLY"; detail:"deliverable is supported only by memory or narrative evidence"}
        else empty end
      ]) as $weak
    | {
        deliverable_id:$id,
        title:($d.title // ""),
        missing_evidence:$missing,
        weak_evidence:$weak,
        deferred:(($d.deferred // false) == true),
        status:(if (($d.deferred // false) == true) then "deferred"
          elif ($missing | length) > 0 then "missing"
          elif ($weak | length) > 0 then "weakly_verified"
          else "satisfied" end)
      };
  (deliverables | map(audit_one(.))) as $reports
  | {
      schema_version:$schema_version,
      case_id:$case_id,
      source_revision:$source_revision,
      objective_id:($objective[0].objective_id // null),
      decision:(if any($reports[]?; .status == "missing" or .status == "weakly_verified" or .status == "deferred") then "blocked" else "complete" end),
      satisfied:($reports | map(select(.status == "satisfied"))),
      missing:($reports | map(select(.status == "missing"))),
      weakly_verified:($reports | map(select(.status == "weakly_verified"))),
      deferred:($reports | map(select(.status == "deferred"))),
      summary:{
        deliverable_count:($reports | length),
        satisfied_count:($reports | map(select(.status == "satisfied")) | length),
        missing_count:($reports | map(select(.status == "missing")) | length),
        weakly_verified_count:($reports | map(select(.status == "weakly_verified")) | length),
        deferred_count:($reports | map(select(.status == "deferred")) | length)
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_br:false,
        closes_beads:false,
        sends_agent_mail:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      },
      artifact_paths:{
        completion_audit_report_json:$report_json,
        missing_evidence_jsonl:$missing_jsonl,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_md,
        objective_normalized_json:$objective_normalized,
        evidence_normalized_json:$evidence_normalized
      }
    }
  ' >"$report_tmp"

mv "$report_tmp" "$report_json"
jq -c '(.missing[]?, .weakly_verified[]?, .deferred[]?)' "$report_json" >"$missing_jsonl"
jq -c '
  {
    schema_version:"franken-engine.objective-completion-audit-event.v1",
    event:"completion_audit_emitted",
    decision:.decision,
    summary:.summary,
    source_revision:.source_revision
  },
  (.missing[]? | {
    schema_version:"franken-engine.objective-completion-audit-event.v1",
    event:"missing_deliverable",
    deliverable_id:.deliverable_id
  }),
  (.weakly_verified[]? | {
    schema_version:"franken-engine.objective-completion-audit-event.v1",
    event:"weakly_verified_deliverable",
    deliverable_id:.deliverable_id
  })
' "$report_json" >"$events_path"
jq -r '
  "# Objective Completion Audit\n\n"
  + "- decision: `" + .decision + "`\n"
  + "- deliverables: `" + (.summary.deliverable_count | tostring) + "`\n"
  + "- satisfied: `" + (.summary.satisfied_count | tostring) + "`\n"
  + "- missing: `" + (.summary.missing_count | tostring) + "`\n"
  + "- weakly verified: `" + (.summary.weakly_verified_count | tostring) + "`\n"
  + "- deferred: `" + (.summary.deferred_count | tostring) + "`\n"
' "$report_json" >"$report_md"

decision="$(jq -r '.decision' "$report_json")"
printf 'completion_audit_report=%s\n' "$report_json"
printf 'completion_audit_decision=%s\n' "$decision"
if [[ "$decision" != "complete" ]]; then
  exit 42
fi
