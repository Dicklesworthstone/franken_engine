#!/usr/bin/env bash
set -euo pipefail

frankenctl_bin="${FRANKENCTL_BIN:-}"
if [[ -z "$frankenctl_bin" ]]; then
  printf 'FRANKENCTL_BIN must point at a built frankenctl binary\n' >&2
  exit 2
fi

if [[ ! -x "$frankenctl_bin" ]]; then
  printf 'FRANKENCTL_BIN is not executable: %s\n' "$frankenctl_bin" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for external trust claim explainer smoke\n' >&2
  exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
workdir="${EXTERNAL_TRUST_CLAIM_EXPLAINER_WORKDIR:-${TMPDIR:-/tmp}/franken-engine-external-trust-claim-explainer-smoke-$$-${timestamp}}"
mkdir -p "$workdir"

artifact_path="${workdir}/artifact.json"
stale_artifact_dir="${workdir}/stale_artifact"
source_path="${workdir}/source.md"
matrix_path="${workdir}/matrix.json"
beads_path="${workdir}/issues.jsonl"
supported_out="${workdir}/supported.json"
missing_bead_out="${workdir}/missing_bead.json"
missing_artifact_out="${workdir}/missing_artifact.json"
stale_out="${workdir}/stale.json"
missing_out="${workdir}/missing.json"

printf '{"proof":"observed"}\n' >"$artifact_path"
printf 'fixture repro lock\n' >"${workdir}/repro.lock"
printf 'Smoke source claim.\n' >"$source_path"
mkdir -p "$stale_artifact_dir"
cat >"${stale_artifact_dir}/manifest.json" <<'JSON'
{
  "schema_version": "franken-engine.proof-artifact-manifest.v1",
  "freshness": {
    "generated_utc": "2026-01-01T00:00:00Z"
  }
}
JSON

jq -n \
  --arg schema_version "franken-engine.claim-to-proof-matrix.v1" \
  --arg artifact_path "$artifact_path" \
  --arg source_path "$source_path" \
  --arg missing_artifact_path "${workdir}/missing_artifact.json" \
  --arg stale_artifact_path "$stale_artifact_dir" \
  '{
    schema_version: $schema_version,
    stale_threshold_days: 30,
    claims: [
      {
        actual_wording_state: "observed",
        allowed_state: "observed",
        artifact_path: $artifact_path,
        claim_id: "FE-CLAIM-SMOKE",
        claim_scope: "evidence",
        claim_text: "Smoke claim.",
        decision: "allow observed smoke fixture",
        downgrade_text: "Smoke downgrade.",
        freshness_days: 0,
        owning_bead: "bd-smoke",
        reason: "Smoke reason.",
        source_path: $source_path,
        source_span: {
          start_line: 1,
          end_line: 1,
          must_contain: "Smoke"
        },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_smoke cargo test -p frankenengine-engine smoke"
      },
      {
        actual_wording_state: "observed",
        allowed_state: "observed",
        artifact_path: $missing_artifact_path,
        claim_id: "FE-CLAIM-MISSING-ARTIFACT",
        claim_scope: "evidence",
        claim_text: "Missing artifact smoke claim.",
        decision: "allow observed smoke fixture",
        downgrade_text: "Smoke downgrade.",
        freshness_days: 0,
        owning_bead: "bd-smoke",
        reason: "Smoke reason.",
        source_path: $source_path,
        source_span: {
          start_line: 1,
          end_line: 1,
          must_contain: "Smoke"
        },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_smoke cargo test -p frankenengine-engine smoke"
      },
      {
        actual_wording_state: "observed",
        allowed_state: "observed",
        artifact_path: $stale_artifact_path,
        claim_id: "FE-CLAIM-STALE",
        claim_scope: "evidence",
        claim_text: "Stale artifact smoke claim.",
        decision: "allow observed smoke fixture",
        downgrade_text: "Smoke downgrade.",
        freshness_days: 0,
        owning_bead: "bd-smoke",
        reason: "Smoke reason.",
        source_path: $source_path,
        source_span: {
          start_line: 1,
          end_line: 1,
          must_contain: "Smoke"
        },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_smoke cargo test -p frankenengine-engine smoke"
      }
    ]
  }' >"$matrix_path"

jq -cn '{id:"bd-smoke", status:"closed", assignee:"EmeraldPine"}' >"$beads_path"

"$frankenctl_bin" claims explain FE-CLAIM-SMOKE \
  --matrix "$matrix_path" \
  --beads-jsonl "$beads_path" \
  --format json \
  --out "$supported_out"

jq -e '
  .schema_version == "franken-engine.external-trust-claim-explainer.v1"
  and .decision == "supported"
  and .artifact.present == true
  and .bead.status == "closed"
  and .mutation_policy.mutates_br == false
  and .renderer_boundary.future_rich_renderer_provider == "/dp/frankentui"
' "$supported_out" >/dev/null

set +e
"$frankenctl_bin" claims explain FE-CLAIM-SMOKE \
  --matrix "$matrix_path" \
  --beads-jsonl "${workdir}/missing_issues.jsonl" \
  --format json \
  --out "$missing_bead_out"
missing_bead_status=$?
set -e

if [[ "$missing_bead_status" -ne 2 ]]; then
  printf 'expected missing Beads snapshot to exit 2, got %s\n' "$missing_bead_status" >&2
  exit 1
fi

jq -e '
  .decision == "fail_closed"
  and (.reason_codes | index("stale_tracker_state") != null)
  and .bead.found == false
' "$missing_bead_out" >/dev/null

set +e
"$frankenctl_bin" claims explain FE-CLAIM-MISSING-ARTIFACT \
  --matrix "$matrix_path" \
  --no-beads \
  --format json \
  --out "$missing_artifact_out"
missing_artifact_status=$?
set -e

if [[ "$missing_artifact_status" -ne 2 ]]; then
  printf 'expected missing artifact to exit 2, got %s\n' "$missing_artifact_status" >&2
  exit 1
fi

jq -e '
  .decision == "fail_closed"
  and (.reason_codes | index("absent_artifact") != null)
  and .artifact.present == false
' "$missing_artifact_out" >/dev/null

set +e
"$frankenctl_bin" claims explain FE-CLAIM-STALE \
  --matrix "$matrix_path" \
  --no-beads \
  --format json \
  --out "$stale_out"
stale_status=$?
set -e

if [[ "$stale_status" -ne 2 ]]; then
  printf 'expected stale artifact to exit 2, got %s\n' "$stale_status" >&2
  exit 1
fi

jq -e '
  .decision == "fail_closed"
  and (.reason_codes | index("stale_artifact") != null)
  and .artifact.freshness_status == "stale"
' "$stale_out" >/dev/null

set +e
"$frankenctl_bin" claims explain FE-CLAIM-MISSING \
  --matrix "$matrix_path" \
  --no-beads \
  --format json \
  --out "$missing_out"
missing_status=$?
set -e

if [[ "$missing_status" -ne 2 ]]; then
  printf 'expected missing claim to exit 2, got %s\n' "$missing_status" >&2
  exit 1
fi

jq -e '
  .decision == "fail_closed"
  and (.reason_codes | index("missing_claim_row") != null)
' "$missing_out" >/dev/null

printf 'external trust claim explainer smoke PASS: %s\n' "$workdir"
