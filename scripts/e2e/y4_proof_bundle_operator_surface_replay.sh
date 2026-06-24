#!/usr/bin/env bash
#
# Y.4 operator proof-bundle surface — replay / drift detector
# (bd-cixqu.25.4, Track Y).
#
# Re-checks a preserved gate run bundle from
# scripts/run_y4_proof_bundle_operator_surface.sh: it re-verifies the preserved
# valid + tampered proof-bundle tars with the operator wrapper and confirms the
# classifications (and the valid bundle's recheck digest) reproduce what the gate
# recorded. A hollow or incomplete bundle cannot masquerade as a real run.
#
# Usage:
#   y4_proof_bundle_operator_surface_replay.sh [bundle <run_dir>]
#   (no args) auto-detects the latest complete bundle, or honours
#   Y4_PROOF_BUNDLE_OPERATOR_REPLAY_RUN_DIR=<dir>.
#
# Exit codes:
#   0  replay reproduced the gate verdicts
#   1  no source bundle found
#   2  incomplete bundle (fail-closed)
#   3  verdict / digest mismatch on replay
#
set -euo pipefail
export TZ=UTC LC_ALL=C LANG=C LANGUAGE=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly COMPONENT="y4_proof_bundle_operator_surface_replay"
readonly WRAPPER="runbooks/scripts/verify_proof_bundle.sh"
readonly ARTIFACT_ROOT="${Y4_PROOF_BUNDLE_OPERATOR_ARTIFACT_ROOT:-${ROOT_DIR}/artifacts/y4_proof_bundle_operator_surface}"

log() { echo "[${COMPONENT}] $*" >&2; }
json_get() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$1" "$2"; }

# Resolve the run dir: explicit arg > env > latest complete under artifact root.
resolve_run_dir() {
  if [[ "${1:-}" == "bundle" && -n "${2:-}" ]]; then
    printf '%s\n' "$2"; return 0
  fi
  if [[ -n "${Y4_PROOF_BUNDLE_OPERATOR_REPLAY_RUN_DIR:-}" ]]; then
    printf '%s\n' "${Y4_PROOF_BUNDLE_OPERATOR_REPLAY_RUN_DIR}"; return 0
  fi
  [[ -d "${ARTIFACT_ROOT}" ]] || return 1
  local d
  for d in $(ls -1d "${ARTIFACT_ROOT}"/*/ 2>/dev/null | sort -r); do
    if [[ -f "${d}/run_manifest.json" && -f "${d}/proof_bundle_valid.tar.gz" ]]; then
      printf '%s\n' "${d%/}"; return 0
    fi
  done
  return 1
}

main() {
  local run_dir
  if ! run_dir="$(resolve_run_dir "$@")"; then
    log "no source bundle found under ${ARTIFACT_ROOT}"; exit 1
  fi
  log "replaying bundle: ${run_dir#"${ROOT_DIR}"/}"

  # Fail-closed completeness check.
  local required=(run_manifest.json proof_bundle_valid.tar.gz proof_bundle_tampered.tar.gz \
                  verdict_valid.json verdict_tampered.json)
  local f
  for f in "${required[@]}"; do
    [[ -f "${run_dir}/${f}" ]] || { log "incomplete bundle: missing ${f}"; exit 2; }
  done

  local replay_dir="${run_dir}/replay"
  mkdir -p "${replay_dir}"

  # Re-verify the valid bundle => verified, exit 0, digest reproduces.
  local rc=0
  bash "${WRAPPER}" verify "${run_dir}/proof_bundle_valid.tar.gz" --via local \
    --installed-lean 4.9.0 --installed-coq 8.19.2 \
    --json-out "${replay_dir}/verdict_valid.json" \
    --artifact-root "${replay_dir}/runs" >/dev/null 2>&1 || rc=$?
  local rclass rdigest oclass odigest
  rclass="$(json_get "${replay_dir}/verdict_valid.json" classification)"
  rdigest="$(json_get "${replay_dir}/verdict_valid.json" recomputed_recheck_digest)"
  oclass="$(json_get "${run_dir}/verdict_valid.json" classification)"
  odigest="$(json_get "${run_dir}/verdict_valid.json" recomputed_recheck_digest)"
  if [[ "${rc}" -ne 0 || "${rclass}" != "verified" || "${rclass}" != "${oclass}" ]]; then
    log "valid-bundle replay mismatch: rc=${rc} replay=${rclass} recorded=${oclass}"; exit 3
  fi
  if [[ -z "${rdigest}" || "${rdigest}" != "${odigest}" ]]; then
    log "valid-bundle digest drift: replay=${rdigest} recorded=${odigest}"; exit 3
  fi

  # Re-verify the tampered bundle => proof_regression, exit 1.
  rc=0
  bash "${WRAPPER}" verify "${run_dir}/proof_bundle_tampered.tar.gz" --via local \
    --installed-lean 4.9.0 \
    --json-out "${replay_dir}/verdict_tampered.json" \
    --artifact-root "${replay_dir}/runs" >/dev/null 2>&1 || rc=$?
  local tclass otclass
  tclass="$(json_get "${replay_dir}/verdict_tampered.json" classification)"
  otclass="$(json_get "${run_dir}/verdict_tampered.json" classification)"
  if [[ "${rc}" -ne 1 || "${tclass}" != "proof_regression" || "${tclass}" != "${otclass}" ]]; then
    log "tampered-bundle replay mismatch: rc=${rc} replay=${tclass} recorded=${otclass}"; exit 3
  fi

  log "REPLAY OK: valid=>verified (digest ${rdigest}) + tampered=>proof_regression reproduced"
  exit 0
}

main "$@"
