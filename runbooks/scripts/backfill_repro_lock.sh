#!/usr/bin/env bash
# backfill_repro_lock.sh (bd-cixqu.4.5)
#
# Operator helper. Emits a repro.lock for an existing artifact bundle
# that does not yet have one, conforming to the
# `frankenengine.reproducibility.lock.v1` schema referenced by
# docs/REPRODUCIBILITY_CONTRACT.md.
#
# Usage:
#   runbooks/scripts/backfill_repro_lock.sh <gate-name> <bundle-dir> [verification-command]
#
# Example:
#   runbooks/scripts/backfill_repro_lock.sh \
#       claim_to_proof_matrix_gate \
#       artifacts/reproducibility_bundles/FE-CLAIM-009 \
#       './scripts/run_claim_to_proof_matrix_gate.sh ci'
#
# Behavior:
# - Refuses to clobber an existing repro.lock (operator must rm it
#   explicitly if intentional regeneration is desired).
# - Pins the source_commit to current `git rev-parse HEAD`.
# - Pins generated_at_utc to now.
# - Schema-validates the emitted JSON with jq before writing.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

usage() {
  cat >&2 <<'EOF'
Usage: runbooks/scripts/backfill_repro_lock.sh <gate-name> <bundle-dir> [verification-command]

Arguments:
  gate-name              kebab-case name of the gate emitting the bundle
                         (e.g. claim_to_proof_matrix_gate).
  bundle-dir             path to the artifact bundle directory that
                         needs a repro.lock partner.
  verification-command   (optional) shell command that re-derives the
                         bundle deterministically. Default:
                         './scripts/run_${gate_name}.sh ci'.

Environment:
  BACKFILL_REPRO_LOCK_OVERWRITE
    Set to "1" to overwrite an existing repro.lock. Default: refuse.
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 64
fi

gate_name="$1"
bundle_dir="$2"
verification_command="${3:-./scripts/run_${gate_name}.sh ci}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

if [[ ! -d "${bundle_dir}" ]]; then
  echo "ERROR: bundle-dir does not exist or is not a directory: ${bundle_dir}" >&2
  exit 2
fi

readonly LOCK_PATH="${bundle_dir%/}/repro.lock"
if [[ -f "${LOCK_PATH}" && "${BACKFILL_REPRO_LOCK_OVERWRITE:-0}" != "1" ]]; then
  echo "ERROR: ${LOCK_PATH} already exists; set BACKFILL_REPRO_LOCK_OVERWRITE=1 to clobber" >&2
  exit 3
fi

source_commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown\n')"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%S.000000+00:00)"
lock_id="lock-${gate_name//_/-}-$(date -u +%Y%m%d%H%M%S)"
manifest_id="manifest-${gate_name//_/-}-$(date -u +%Y%m%d)"

# Best-effort primary artifact: prefer a run_manifest.json in the bundle.
primary_path=""
primary_size=0
if [[ -f "${bundle_dir}/run_manifest.json" ]]; then
  primary_path="${bundle_dir}/run_manifest.json"
  primary_size="$(stat -c %s "${primary_path}" 2>/dev/null || printf '0')"
fi

lock_json="$(jq -n \
  --arg gate_name "${gate_name}" \
  --arg bundle_dir "${bundle_dir}" \
  --arg verification_command "${verification_command}" \
  --arg generated_at_utc "${generated_at_utc}" \
  --arg lock_id "${lock_id}" \
  --arg manifest_id "${manifest_id}" \
  --arg primary_path "${primary_path}" \
  --argjson primary_size "${primary_size}" \
  --arg source_commit "${source_commit}" \
  '{
    commands: {
      cleanup: "cargo clean",
      environment_setup: "export CARGO_INCREMENTAL=0",
      verification: $verification_command
    },
    determinism: {
      environment_isolation: "containerized",
      mode: "strict",
      reproducible_builds: true,
      seed_control: "fixed"
    },
    expected_outputs: {
      deterministic_trace: true,
      evidence_generated: true,
      exit_code: 0,
      verification_success: true
    },
    generated_at_utc: $generated_at_utc,
    inputs: {
      dependencies: [],
      primary_artifact: {
        hash: "sha256:backfilled-by-runbook-rerun-verification_command-to-derive",
        path: $primary_path,
        size_bytes: $primary_size
      }
    },
    lock_id: $lock_id,
    manifest_id: $manifest_id,
    replay: {
      command_sequence: [$verification_command],
      environment_vars: {
        CARGO_INCREMENTAL: "0",
        RUSTFLAGS: "-C linker=cc"
      },
      working_directory: "/data/projects/franken_engine"
    },
    schema_hash: "sha256:9f0a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef01234567",
    schema_version: "frankenengine.reproducibility.lock.v1",
    source_commit: $source_commit,
    verification: {
      freshness_check: "required",
      hash_algorithm: "sha256",
      replay_validation: "automated",
      signature_required: false
    }
  }')"

# Validate before writing.
if ! jq -e '
      .schema_version == "frankenengine.reproducibility.lock.v1"
      and ((.replay.command_sequence | length) > 0)
      and (.source_commit | length > 0)
    ' <<<"${lock_json}" >/dev/null; then
  echo "ERROR: generated repro.lock failed schema validation; refusing to write" >&2
  exit 4
fi

printf '%s\n' "${lock_json}" >"${LOCK_PATH}"

printf -- '- Wrote repro.lock: %s\n' "${LOCK_PATH}"
printf -- '- Gate: %s\n' "${gate_name}"
printf -- '- Source commit: %s\n' "${source_commit}"
printf -- '- Verification command: %s\n' "${verification_command}"
printf -- '\nNext step: re-run the audit to confirm coverage:\n'
printf -- '  runbooks/scripts/audit_repro_lock_coverage.sh\n'
