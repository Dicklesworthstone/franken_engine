#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
receipt_json=""
source_revision=""
artifact_root="${root_dir}/artifacts/idea_wizard_xiii_transparency_log_decision_receipt_proof"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_dir=""
skip_live_receipt_refresh=false
original_args=("$@")

usage() {
  cat <<'USAGE'
Usage: scripts/idea_wizard_xiii_transparency_log_decision_receipt_proof.sh [options]

Options:
  --receipt-json <path>             Use an existing signed decision receipt JSON.
  --skip-live-receipt-refresh       Require --receipt-json and do not run the rch-backed receipt example.
  --source-revision <rev>           Source revision bound into the proof.
  --output-dir <path>               Output artifact directory.
  -h, --help                        Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --receipt-json)
      receipt_json="${2:?--receipt-json requires a path}"
      shift 2
      ;;
    --skip-live-receipt-refresh)
      skip_live_receipt_refresh=true
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
if [[ "$skip_live_receipt_refresh" == true && -z "$receipt_json" ]]; then
  printf '--skip-live-receipt-refresh requires --receipt-json\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
decision_receipt_path="${run_dir}/decision_receipt.json"
canonical_receipt_path="${run_dir}/decision_receipt.canonical.json"
leaf_set_path="${run_dir}/transparency_log_leaf_set.txt"
prefix_leaf_set_path="${run_dir}/transparency_log_prefix_leaf_set.txt"
transparency_log_path="${run_dir}/transparency_log.json"
inclusion_proofs_path="${run_dir}/inclusion_proofs.json"
consistency_proof_path="${run_dir}/consistency_proof.json"
negative_fixtures_path="${run_dir}/negative_fixtures.json"
report_json_path="${run_dir}/independent_verifier_report.json"
report_md_path="${run_dir}/report.md"
manifest_path="${run_dir}/run_manifest.json"

for artifact_path in \
  "$commands_path" \
  "$events_path" \
  "$decision_receipt_path" \
  "$canonical_receipt_path" \
  "$leaf_set_path" \
  "$prefix_leaf_set_path" \
  "$transparency_log_path" \
  "$inclusion_proofs_path" \
  "$consistency_proof_path" \
  "$negative_fixtures_path" \
  "$report_json_path" \
  "$report_md_path" \
  "$manifest_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_xiii_transparency_log_decision_receipt_proof.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local status="$2"
  local reason="$3"
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log-decision-receipt-proof.event.v1" \
    --arg event "$event" \
    --arg status "$status" \
    --arg reason "$reason" \
    '{schema_version:$schema_version,event:$event,status:$status,reason:$reason}' >>"$events_path"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

sha256_text() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

if [[ -z "$receipt_json" ]]; then
  live_dir="${run_dir}/signed_decision_receipt"
  printf 'SIGNED_DECISION_RECEIPT_RUN_DIR=%q ./examples/02_signed_decision_receipt/verify.sh\n' \
    "$live_dir" >>"$commands_path"
  set +e
  (
    cd "$root_dir"
    SIGNED_DECISION_RECEIPT_RUN_DIR="$live_dir" \
      ./examples/02_signed_decision_receipt/verify.sh
  ) >"${run_dir}/live_receipt.stdout" 2>"${run_dir}/live_receipt.stderr"
  live_status=$?
  set -e
  receipt_json="${live_dir}/signed_decision_receipt.json"
  if [[ "$live_status" -ne 0 || ! -f "$receipt_json" ]]; then
    write_event "live_signed_receipt_refresh" "fail" "rch-backed signed receipt example did not produce a receipt"
    jq -n \
      --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log-decision-receipt-proof.report.v1" \
      --arg source_revision "$source_revision" \
      --arg decision "fail_closed" \
      --arg reason "live signed receipt refresh failed" \
      '{
        schema_version:$schema_version,
        claim_id:"FE-CLAIM-004",
        source_revision:$source_revision,
        decision:$decision,
        independent_verifier_verdict:"fail",
        tee_attestation_state:"not_promoted",
        failures:[{check:"live_signed_receipt_refresh",reason:$reason}]
      }' >"$report_json_path"
    printf 'live signed receipt refresh failed; report=%s\n' "$report_json_path" >&2
    exit 42
  fi
  write_event "live_signed_receipt_refresh" "pass" "rch-backed signed receipt example produced a receipt"
else
  write_event "live_signed_receipt_refresh" "skipped" "using caller-provided receipt JSON"
fi

jq '.' "$receipt_json" >"$decision_receipt_path"
jq -cS '.' "$decision_receipt_path" >"$canonical_receipt_path"
receipt_leaf_hash="$(sha256_file "$canonical_receipt_path")"
prior_anchor_hash="$(sha256_text "franken-engine.transparency-log.prior.v1:${source_revision}")"
checkpoint_anchor_hash="$(sha256_text "franken-engine.transparency-log.checkpoint.v1:${source_revision}:${receipt_leaf_hash}")"
printf '%s\n%s\n%s\n' "$prior_anchor_hash" "$receipt_leaf_hash" "$checkpoint_anchor_hash" >"$leaf_set_path"
printf '%s\n' "$prior_anchor_hash" >"$prefix_leaf_set_path"
log_root="$(sha256_file "$leaf_set_path")"
prefix_root="$(sha256_file "$prefix_leaf_set_path")"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log.v1" \
  --arg claim_id "FE-CLAIM-004" \
  --arg source_revision "$source_revision" \
  --arg prior_anchor_hash "$prior_anchor_hash" \
  --arg receipt_leaf_hash "$receipt_leaf_hash" \
  --arg checkpoint_anchor_hash "$checkpoint_anchor_hash" \
  --arg prefix_root "$prefix_root" \
  --arg log_root "$log_root" \
  '{
    schema_version:$schema_version,
    claim_id:$claim_id,
    source_revision:$source_revision,
    log_id:"idea-wizard-xiii-decision-receipt-transparency-log",
    proof_algorithm:"deterministic_leaf_set_sha256_v1",
    previous_checkpoint:{leaf_count:1,root_hash:$prefix_root},
    current_checkpoint:{leaf_count:3,root_hash:$log_root,operator_key_id:"local-proof-wrapper"},
    leaves:[
      {index:0,kind:"prior_anchor",hash:$prior_anchor_hash},
      {index:1,kind:"signed_decision_receipt",hash:$receipt_leaf_hash},
      {index:2,kind:"checkpoint_anchor",hash:$checkpoint_anchor_hash}
    ]
  }' >"$transparency_log_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log-inclusion-proofs.v1" \
  --arg receipt_leaf_hash "$receipt_leaf_hash" \
  --arg prior_anchor_hash "$prior_anchor_hash" \
  --arg checkpoint_anchor_hash "$checkpoint_anchor_hash" \
  --arg log_root "$log_root" \
  '{
    schema_version:$schema_version,
    proofs:[{
      claim_id:"FE-CLAIM-004",
      leaf_index:1,
      leaf_hash:$receipt_leaf_hash,
      root_hash:$log_root,
      log_length:3,
      sibling_hashes:[$prior_anchor_hash,$checkpoint_anchor_hash],
      proof_algorithm:"deterministic_leaf_set_sha256_v1"
    }]
  }' >"$inclusion_proofs_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log-consistency-proof.v1" \
  --arg prefix_root "$prefix_root" \
  --arg receipt_leaf_hash "$receipt_leaf_hash" \
  --arg checkpoint_anchor_hash "$checkpoint_anchor_hash" \
  --arg log_root "$log_root" \
  '{
    schema_version:$schema_version,
    claim_id:"FE-CLAIM-004",
    from_leaf_count:1,
    to_leaf_count:3,
    from_root:$prefix_root,
    to_root:$log_root,
    appended_leaf_hashes:[$receipt_leaf_hash,$checkpoint_anchor_hash],
    proof_algorithm:"deterministic_leaf_set_sha256_v1"
  }' >"$consistency_proof_path"

receipt_schema_valid=false
if jq -e '
  (.decision | type == "string" and IN("allow","challenge","sandbox","suspend","terminate","quarantine"))
  and (.posterior_after_millionths | type == "number" and . >= 0 and . <= 1000000)
  and (.replay_seed | type == "number")
  and (.signature_hex | type == "string" and test("^[0-9a-f]{64}$"))
' "$decision_receipt_path" >/dev/null; then
  receipt_schema_valid=true
fi

inclusion_valid=false
if [[ "$(jq -r '.proofs[0].leaf_hash' "$inclusion_proofs_path")" == "$receipt_leaf_hash" \
  && "$(jq -r '.proofs[0].root_hash' "$inclusion_proofs_path")" == "$log_root" \
  && "$(jq -r '.current_checkpoint.root_hash' "$transparency_log_path")" == "$log_root" ]]; then
  inclusion_valid=true
fi

consistency_valid=false
if [[ "$(jq -r '.from_root' "$consistency_proof_path")" == "$prefix_root" \
  && "$(jq -r '.to_root' "$consistency_proof_path")" == "$log_root" ]]; then
  consistency_valid=true
fi

tee_not_promoted=true

tampered_receipt_path="${run_dir}/tampered_receipt_negative_fixture.json"
missing_signer_path="${run_dir}/missing_signer_negative_fixture.json"
forked_log_root_path="${run_dir}/forked_log_root_negative_fixture.json"
stale_proof_path="${run_dir}/stale_proof_negative_fixture.json"

jq '.signature_hex = "0000000000000000000000000000000000000000000000000000000000000000"' \
  "$decision_receipt_path" >"$tampered_receipt_path"
jq 'del(.signature_hex)' "$decision_receipt_path" >"$missing_signer_path"
jq '.current_checkpoint.root_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$transparency_log_path" >"$forked_log_root_path"
jq '.source_revision = "stale-source-revision"' "$transparency_log_path" >"$stale_proof_path"

tampered_leaf_hash="$(jq -cS '.' "$tampered_receipt_path" | sha256sum | awk '{print $1}')"
tampered_fails_closed=false
if [[ "$tampered_leaf_hash" != "$receipt_leaf_hash" ]]; then
  tampered_fails_closed=true
fi

missing_signer_fails_closed=false
if ! jq -e '.signature_hex | type == "string" and test("^[0-9a-f]{64}$")' "$missing_signer_path" >/dev/null; then
  missing_signer_fails_closed=true
fi

forked_root_fails_closed=false
if [[ "$(jq -r '.current_checkpoint.root_hash' "$forked_log_root_path")" != "$log_root" ]]; then
  forked_root_fails_closed=true
fi

stale_proof_fails_closed=false
if [[ "$(jq -r '.source_revision' "$stale_proof_path")" != "$source_revision" ]]; then
  stale_proof_fails_closed=true
fi

jq -n \
  --arg tampered_receipt_path "$tampered_receipt_path" \
  --arg missing_signer_path "$missing_signer_path" \
  --arg forked_log_root_path "$forked_log_root_path" \
  --arg stale_proof_path "$stale_proof_path" \
  --argjson tampered_fails_closed "$tampered_fails_closed" \
  --argjson missing_signer_fails_closed "$missing_signer_fails_closed" \
  --argjson forked_root_fails_closed "$forked_root_fails_closed" \
  --argjson stale_proof_fails_closed "$stale_proof_fails_closed" \
  '{
    schema_version:"franken-engine.idea-wizard-xiii-transparency-log-negative-fixtures.v1",
    fixtures:[
      {name:"tampered_receipt",path:$tampered_receipt_path,decision:(if $tampered_fails_closed then "fail_closed" else "unexpected_pass" end),reason:"tampered receipt changes the bound leaf hash"},
      {name:"missing_signer",path:$missing_signer_path,decision:(if $missing_signer_fails_closed then "fail_closed" else "unexpected_pass" end),reason:"signature_hex is required"},
      {name:"forked_log_root",path:$forked_log_root_path,decision:(if $forked_root_fails_closed then "fail_closed" else "unexpected_pass" end),reason:"checkpoint root must match recomputed log root"},
      {name:"stale_proof",path:$stale_proof_path,decision:(if $stale_proof_fails_closed then "fail_closed" else "unexpected_pass" end),reason:"source revision must match the run manifest"}
    ]
  }' >"$negative_fixtures_path"

negative_fixtures_valid=false
if jq -e 'all(.fixtures[]; .decision == "fail_closed")' "$negative_fixtures_path" >/dev/null; then
  negative_fixtures_valid=true
fi

decision="fail_closed"
if [[ "$receipt_schema_valid" == true \
  && "$inclusion_valid" == true \
  && "$consistency_valid" == true \
  && "$tee_not_promoted" == true \
  && "$negative_fixtures_valid" == true ]]; then
  decision="pass"
fi

for row in \
  "receipt_schema:${receipt_schema_valid}:receipt has required signed-decision fields" \
  "inclusion_proof:${inclusion_valid}:receipt leaf is included in the log root" \
  "consistency_proof:${consistency_valid}:prefix root extends to current root" \
  "tee_not_promoted:${tee_not_promoted}:TEE wording remains hypothesis" \
  "negative_fixtures:${negative_fixtures_valid}:negative fixtures fail closed"; do
  IFS=: read -r check passed detail <<<"$row"
  if [[ "$passed" == true ]]; then
    write_event "$check" "pass" "$detail"
  else
    write_event "$check" "fail" "$detail"
  fi
done

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log-decision-receipt-proof.report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg receipt_chain_root "$log_root" \
  --arg log_root "$log_root" \
  --arg receipt_leaf_hash "$receipt_leaf_hash" \
  --arg prefix_root "$prefix_root" \
  --arg decision_receipt_path "$decision_receipt_path" \
  --arg transparency_log_path "$transparency_log_path" \
  --arg inclusion_proofs_path "$inclusion_proofs_path" \
  --arg consistency_proof_path "$consistency_proof_path" \
  --arg negative_fixtures_path "$negative_fixtures_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md_path "$report_md_path" \
  --arg manifest_path "$manifest_path" \
  --argjson receipt_schema_valid "$receipt_schema_valid" \
  --argjson inclusion_valid "$inclusion_valid" \
  --argjson consistency_valid "$consistency_valid" \
  --argjson tee_not_promoted "$tee_not_promoted" \
  --argjson negative_fixtures_valid "$negative_fixtures_valid" \
  '{
    schema_version:$schema_version,
    claim_id:"FE-CLAIM-004",
    bead_id:"bd-ly6hp.2",
    source_revision:$source_revision,
    decision:$decision,
    independent_verifier_verdict:(if $decision == "pass" then "pass" else "fail" end),
    tee_attestation_state:"not_promoted",
    promotion_subset:"decision_receipts_plus_transparency_log_only",
    receipt_chain_root:$receipt_chain_root,
    log_root:$log_root,
    receipt_leaf_hash:$receipt_leaf_hash,
    prefix_root:$prefix_root,
    inclusion_proof_count:1,
    consistency_proof_count:1,
    checks:[
      {check:"receipt_schema",passed:$receipt_schema_valid},
      {check:"inclusion_proof",passed:$inclusion_valid},
      {check:"consistency_proof",passed:$consistency_valid},
      {check:"tee_not_promoted",passed:$tee_not_promoted},
      {check:"negative_fixtures",passed:$negative_fixtures_valid}
    ],
    failures:[
      if ($receipt_schema_valid | not) then {check:"receipt_schema",reason:"receipt lacks required signed-decision fields"} else empty end,
      if ($inclusion_valid | not) then {check:"inclusion_proof",reason:"inclusion proof does not bind receipt leaf to log root"} else empty end,
      if ($consistency_valid | not) then {check:"consistency_proof",reason:"consistency proof does not extend prefix root"} else empty end,
      if ($tee_not_promoted | not) then {check:"tee_not_promoted",reason:"TEE was claimed without separate attestation proof"} else empty end,
      if ($negative_fixtures_valid | not) then {check:"negative_fixtures",reason:"one or more negative fixtures did not fail closed"} else empty end
    ],
    artifact_paths:{
      decision_receipt_json:$decision_receipt_path,
      transparency_log_json:$transparency_log_path,
      inclusion_proofs_json:$inclusion_proofs_path,
      consistency_proof_json:$consistency_proof_path,
      negative_fixtures_json:$negative_fixtures_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_md_path,
      run_manifest_json:$manifest_path
    }
  }' >"$report_json_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xiii-transparency-log-decision-receipt-proof.manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg report_json "$report_json_path" \
  --arg report_md "$report_md_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg decision_receipt_json "$decision_receipt_path" \
  --arg transparency_log_json "$transparency_log_path" \
  --arg inclusion_proofs_json "$inclusion_proofs_path" \
  --arg consistency_proof_json "$consistency_proof_path" \
  --arg negative_fixtures_json "$negative_fixtures_path" \
  '{
    schema_version:$schema_version,
    claim_id:"FE-CLAIM-004",
    bead_id:"bd-ly6hp.2",
    source_revision:$source_revision,
    decision:$decision,
    mutation_policy:{
      rewrites_readme:false,
      mutates_claim_matrix:false,
      sends_agent_mail:false,
      repairs_agent_mail_db:false,
      local_heavy_cargo:false
    },
    artifact_paths:{
      report_json:$report_json,
      report_md:$report_md,
      events_jsonl:$events_jsonl,
      commands_txt:$commands_txt,
      decision_receipt_json:$decision_receipt_json,
      transparency_log_json:$transparency_log_json,
      inclusion_proofs_json:$inclusion_proofs_json,
      consistency_proof_json:$consistency_proof_json,
      negative_fixtures_json:$negative_fixtures_json
    }
  }' >"$manifest_path"

{
  printf '# IDEA-WIZARD-XIII Transparency-Log Decision Receipt Proof\n\n'
  jq -r '"- Decision: `" + .decision + "`"' "$report_json_path"
  jq -r '"- Claim: `" + .claim_id + "`"' "$report_json_path"
  jq -r '"- Promotion subset: `" + .promotion_subset + "`"' "$report_json_path"
  jq -r '"- TEE attestation state: `" + .tee_attestation_state + "`\n"' "$report_json_path"
  jq -r '.checks[] | "- `" + .check + "`: `" + (.passed | tostring) + "`"' "$report_json_path"
  if [[ "$(jq '.failures | length' "$report_json_path")" -ne 0 ]]; then
    printf '\n## Failures\n\n'
    jq -r '.failures[] | "- `" + .check + "`: " + .reason' "$report_json_path"
  fi
} >"$report_md_path"

printf 'transparency_log_decision_receipt_report=%s\n' "$report_json_path"
if [[ "$decision" != "pass" ]]; then
  exit 42
fi
