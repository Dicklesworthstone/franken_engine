#!/usr/bin/env bash
#
# Y.4 — Third-party-verifiable proof-bundle operator surface gate
# (bd-cixqu.25.4, Track Y).
#
# Composition gate that proves the Y.4 operator surface works end-to-end against
# REAL artifacts (no mocks): it exports a real Y.1 proof bundle
# (scripts/export_proof_bundle.sh), drives the operator wrapper
# (runbooks/scripts/verify_proof_bundle.sh), and asserts the wrapper classifies
# every outcome correctly and keeps the two outcome dimensions distinct.
#
# The `ci` gate fails closed unless all pins hold:
#   PIN 1  round-trip: a valid bundle verifies (classification=verified, exit 0)
#          and the digest the wrapper records equals the bundle trust anchor;
#   PIN 2  tamper fails closed (classification=proof_regression, exit 1) and the
#          failing proof is named;
#   PIN 3  version drift is classified DISTINCTLY from regression: a drifted
#          toolchain on the SAME valid bundle is version_drift (advisory exit 0),
#          and --strict-version promotes it to exit 2 — never proof_regression;
#   PIN 4  anti-drift: the wrapper's Y.2 image + gate constants agree with the
#          Rust canonical constants (PROOF_BUNDLE_VERIFIER_IMAGE / _GATE) and the
#          public doc's referenced surfaces all resolve to real files;
#   PIN 5  (docker-conditional) the clean-room docker path verifies the same
#          valid bundle; SKIPPED (logged, not silently passed) if docker absent.
#
# Per bd-cixqu.45 logging discipline: a content-addressed bundle is written under
# artifacts/y4_proof_bundle_operator_surface/<UTC-ts>/ with events.jsonl,
# commands.txt, summary.txt, the preserved valid+tampered tars, the captured
# operator verdicts, and run_manifest.json carrying per-artifact sha256.
#
# This gate is bash + python3 (+ optional docker) only; it does NOT route through
# rch (no cargo build is involved).
#
# Modes:
#   ci | gate     run all pins + emit RGC bundle (default)
#   -h | --help   usage
#
set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly COMPONENT="y4_proof_bundle_operator_surface"
readonly BEAD_ID="bd-cixqu.25.4"
readonly MANIFEST_SCHEMA="franken-engine.proof-artifact-manifest.v1"
readonly EXPORT_TOOL="scripts/export_proof_bundle.sh"
readonly WRAPPER="runbooks/scripts/verify_proof_bundle.sh"
readonly Y2_GATE="scripts/run_y2_proof_bundle_verifier.sh"
readonly RUST_CONSTS="crates/franken-engine/src/ga_exit_evidence_package.rs"
readonly PUBLIC_DOC="docs/PROOF_BUNDLE_VERIFICATION.md"
readonly PROOF_SCHEMA="franken-engine.theorem-backed-compiler.proof.v1"
readonly ARTIFACT_ROOT="${Y4_PROOF_BUNDLE_OPERATOR_ARTIFACT_ROOT:-${ROOT_DIR}/artifacts/${COMPONENT}}"

usage() {
  cat >&2 <<EOF
usage: $0 [ci|gate]   run all Y.4 pins + emit RGC bundle (default)
       $0 -h | --help

Exit codes:
  0  gate passed
  1  gate failed (a pin failed, fail-closed)
  2  CLI / environment error
EOF
}

die() { echo "[${COMPONENT}] ERROR: $*" >&2; exit 2; }

# --- RGC bundle plumbing -----------------------------------------------------
RUN_DIR=""; EVENTS_PATH=""; COMMANDS_PATH=""; STEP_DIR=""; STEP_SEQ=0; TRACE_ID=""

init_run_bundle() {
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="${ARTIFACT_ROOT}/${ts}"
  EVENTS_PATH="${RUN_DIR}/events.jsonl"
  COMMANDS_PATH="${RUN_DIR}/commands.txt"
  STEP_DIR="${RUN_DIR}/step_logs"
  TRACE_ID="trace-${COMPONENT}-${ts}"
  mkdir -p "${STEP_DIR}"
  : >"${EVENTS_PATH}"; : >"${COMMANDS_PATH}"
  cat >"${RUN_DIR}/trace_ids.json" <<EOF
{
  "trace_id": "${TRACE_ID}",
  "decision_id": "decision-${COMPONENT}-${ts}",
  "policy_id": "policy-${COMPONENT}-v1"
}
EOF
}

log_event() {
  local kind="$1" status="$2" detail="$3" now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$EVENTS_PATH" "$kind" "$status" "$detail" "$now" "$TRACE_ID" "$COMPONENT" <<'PY'
import json, sys
path, kind, status, detail, now, trace, comp = sys.argv[1:8]
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({
        "schema_id": "franken-engine.evidence-record.v1",
        "trace_id": trace, "component": comp, "kind": kind,
        "status": status, "detail": detail, "generated_utc": now,
    }, sort_keys=True) + "\n")
PY
}

record_cmd() { printf '$ %s\n' "$*" >>"${COMMANDS_PATH}"; }

# Author a valid fixture proof source. Arg: <dir>.
write_fixture_source() {
  local dir="$1"; mkdir -p "${dir}"
  FX_DIR="${dir}" FX_SCHEMA="${PROOF_SCHEMA}" python3 <<'PY'
import hashlib, json, os
d = os.environ["FX_DIR"]; schema = os.environ["FX_SCHEMA"]
for claim_id, track, kind in [
    ("FE-CLAIM-016", "G.2,G.3", "formal-spec-isomorphism"),
    ("FE-CLAIM-020", "G.7,G.8", "theorem-backed-compiler"),
]:
    proof = {"schema_version": schema, "claim_id": claim_id, "track": track,
             "proof_kind": kind, "verdict": "proven",
             "generated_utc": "2026-01-01T00:00:00Z", "source_module": "y4-gate-fixture"}
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    proof["content_hash"] = "sha256:" + hashlib.sha256(enc).hexdigest()
    with open(os.path.join(d, claim_id + ".proof.json"), "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2, sort_keys=True); fh.write("\n")
PY
}

# jq-free field read from a JSON file. Args: <file> <key>.
json_get() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$1" "$2"; }

# Run the wrapper. Args: <bundle> <verdict-out> <extra...>. Echoes nothing;
# returns the wrapper exit code.
run_wrapper() {
  local bundle="$1" verdict_out="$2"; shift 2
  local seq logf
  seq="$(printf '%03d' "${STEP_SEQ}")"
  logf="${STEP_DIR}/${seq}_wrapper.log"
  STEP_SEQ=$((STEP_SEQ + 1))
  record_cmd "bash ${WRAPPER} verify ${bundle} --via local --json-out ${verdict_out} $*"
  local rc=0
  bash "${WRAPPER}" verify "${bundle}" --via local --json-out "${verdict_out}" \
    --artifact-root "${RUN_DIR}/wrapper_runs" "$@" >"${logf}" 2>&1 || rc=$?
  echo "  -> exit ${rc} (log: ${logf#"${ROOT_DIR}"/})" >>"${COMMANDS_PATH}"
  return "${rc}"
}

write_manifest() {
  local verdict="$1"; shift
  local now; now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RUN_DIR="${RUN_DIR}" SCHEMA="${MANIFEST_SCHEMA}" COMPONENT_ENV="${COMPONENT}" \
  BEAD="${BEAD_ID}" TRACE_ID="${TRACE_ID}" VERDICT="${verdict}" NOW="${now}" \
  PINS="$*" python3 <<'PY'
import hashlib, json, os
run_dir = os.environ["RUN_DIR"]
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()
artifacts = {}
for dirpath, _dirs, files in os.walk(run_dir):
    for f in files:
        full = os.path.join(dirpath, f); rel = os.path.relpath(full, run_dir)
        if rel == "run_manifest.json":
            continue
        try:
            artifacts[rel] = sha256(full)
        except OSError:
            pass
pin_tokens = os.environ["PINS"].split()
pins = {}
for tok in pin_tokens:
    if "=" in tok:
        k, v = tok.split("=", 1); pins[k] = v
manifest = {
    "schema_id": os.environ["SCHEMA"], "component": os.environ["COMPONENT_ENV"],
    "bead_id": os.environ["BEAD"], "scope": "Y.4 operator proof-bundle verification surface",
    "trace_id": os.environ["TRACE_ID"], "generated_utc": os.environ["NOW"],
    "verdict": os.environ["VERDICT"], "pins": pins,
    "host_facts": {"uname": os.uname().sysname + " " + os.uname().release + " " + os.uname().machine},
    "operator_verification": {
        "rerun": "./scripts/run_y4_proof_bundle_operator_surface.sh ci",
        "replay": "./scripts/e2e/y4_proof_bundle_operator_surface_replay.sh",
        "doc": "docs/PROOF_BUNDLE_VERIFICATION.md",
    },
    "artifact_content_hashes": artifacts,
}
with open(os.path.join(run_dir, "run_manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True); fh.write("\n")
PY
}

run_ci() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"
  [[ -f "${ROOT_DIR}/${WRAPPER}" ]] || die "wrapper not found: ${WRAPPER}"
  [[ -f "${ROOT_DIR}/${EXPORT_TOOL}" ]] || die "exporter not found: ${EXPORT_TOOL}"
  init_run_bundle
  log_event "gate" "started" "${BEAD_ID} Y.4 operator proof-bundle surface gate"
  echo "[${COMPONENT}] run bundle: ${RUN_DIR#"${ROOT_DIR}"/}"

  local pin1="fail" pin2="fail" pin3="fail" pin4="fail" pin5="skip" overall="pass"
  local work="${RUN_DIR}/work"; mkdir -p "${work}"

  # --- export a real valid bundle ---
  local fx="${work}/src" out="${work}/export"
  write_fixture_source "${fx}"
  record_cmd "bash ${EXPORT_TOOL} export ${fx} ${out}"
  if ! bash "${EXPORT_TOOL}" export "${fx}" "${out}" >"${STEP_DIR}/export.log" 2>&1; then
    log_event "export" "failed" "Y.1 export did not complete"
    write_manifest "fail" "pin1=${pin1}" "pin2=${pin2}" "pin3=${pin3}" "pin4=${pin4}" "pin5=${pin5}"
    echo "[${COMPONENT}] GATE FAIL: fixture export failed" >&2; return 1
  fi
  local valid="${out}/proof_bundle.tar.gz"
  [[ -f "${valid}" ]] || { echo "[${COMPONENT}] GATE FAIL: no exported tar" >&2; return 1; }
  cp "${valid}" "${RUN_DIR}/proof_bundle_valid.tar.gz"
  local anchor; anchor="$(json_get "${out}/bundle_manifest.json" recheck_digest_sha256)"

  # --- PIN 1: round-trip verify ---
  local rc=0
  run_wrapper "${valid}" "${RUN_DIR}/verdict_valid.json" --installed-lean 4.7.0 --installed-coq 8.19.2 || rc=$?
  local vclass vdigest
  vclass="$(json_get "${RUN_DIR}/verdict_valid.json" classification)"
  vdigest="$(json_get "${RUN_DIR}/verdict_valid.json" recomputed_recheck_digest)"
  if [[ "${rc}" -eq 0 && "${vclass}" == "verified" && -n "${anchor}" && "${vdigest}" == "${anchor}" ]]; then
    pin1="pass"; log_event "pin1" "pass" "verified; recorded digest == trust anchor (${anchor})"
  else
    log_event "pin1" "failed" "rc=${rc} class=${vclass} digest=${vdigest} anchor=${anchor}"
  fi

  # --- PIN 2: tamper fails closed ---
  local tstage="${work}/tamper"; mkdir -p "${tstage}"
  tar -xzf "${valid}" -C "${tstage}"
  local victim; victim="$(find "${tstage}" -name '*.proof.json' | sort | head -n1)"
  VICTIM="${victim}" python3 -c '
import json, os
p = os.environ["VICTIM"]; proof = json.load(open(p))
proof["source_module"] = "tampered-after-export"
json.dump(proof, open(p, "w"), indent=2, sort_keys=True); open(p, "a").write("\n")'
  local broot; broot="$(cd "${tstage}" && find . -maxdepth 1 -mindepth 1 -type d | head -n1)"; broot="${broot#./}"
  ( cd "${tstage}" && tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
      --numeric-owner -czf "${RUN_DIR}/proof_bundle_tampered.tar.gz" "${broot}" )
  rc=0
  run_wrapper "${RUN_DIR}/proof_bundle_tampered.tar.gz" "${RUN_DIR}/verdict_tampered.json" --installed-lean 4.7.0 || rc=$?
  local tclass tfail
  tclass="$(json_get "${RUN_DIR}/verdict_tampered.json" classification)"
  tfail="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("failing_claims",[])))' "${RUN_DIR}/verdict_tampered.json" 2>/dev/null || echo 0)"
  if [[ "${rc}" -eq 1 && "${tclass}" == "proof_regression" && "${tfail}" -ge 1 ]]; then
    pin2="pass"; log_event "pin2" "pass" "tampered => proof_regression, exit 1, ${tfail} failing claim(s)"
  else
    log_event "pin2" "failed" "rc=${rc} class=${tclass} failing=${tfail}"
  fi

  # --- PIN 3: version drift is distinct from regression ---
  # Bundle pins lean v4.7.0 (ADR-0007); an operator on a different toolchain
  # (here 4.6.0) drifts. 4.7.0 is now the aligned case, so the drift fixture
  # must use a non-pin version.
  local drift_ok=1
  rc=0
  run_wrapper "${valid}" "${RUN_DIR}/verdict_drift.json" --installed-lean 4.6.0 || rc=$?
  local dclass; dclass="$(json_get "${RUN_DIR}/verdict_drift.json" classification)"
  [[ "${rc}" -eq 0 && "${dclass}" == "version_drift" ]] || drift_ok=0
  rc=0
  run_wrapper "${valid}" "${RUN_DIR}/verdict_strict.json" --installed-lean 4.6.0 --strict-version || rc=$?
  local sclass; sclass="$(json_get "${RUN_DIR}/verdict_strict.json" classification)"
  [[ "${rc}" -eq 2 && "${sclass}" == "version_drift" ]] || drift_ok=0
  if [[ "${drift_ok}" -eq 1 ]]; then
    pin3="pass"; log_event "pin3" "pass" "drift advisory exit0 + strict exit2, never regression"
  else
    log_event "pin3" "failed" "drift=${dclass} strict=${sclass}"
  fi

  # --- PIN 4: anti-drift constants + doc resolution ---
  if assert_constants_agree && assert_doc_resolves; then
    pin4="pass"; log_event "pin4" "pass" "wrapper Y.2 constants == Rust canonical + doc surfaces resolve"
  else
    log_event "pin4" "failed" "constant drift or unresolved doc reference"
  fi

  # --- PIN 5: docker clean-room (conditional) ---
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    rc=0
    record_cmd "bash ${WRAPPER} verify ${valid} --via docker --json-out ${RUN_DIR}/verdict_docker.json"
    bash "${WRAPPER}" verify "${valid}" --via docker \
      --json-out "${RUN_DIR}/verdict_docker.json" \
      --artifact-root "${RUN_DIR}/wrapper_runs" >"${STEP_DIR}/docker.log" 2>&1 || rc=$?
    local kclass; kclass="$(json_get "${RUN_DIR}/verdict_docker.json" classification 2>/dev/null || echo "")"
    if [[ "${rc}" -eq 0 && "${kclass}" == "verified" ]]; then
      pin5="pass"; log_event "pin5" "pass" "clean-room docker path verified the valid bundle"
    else
      pin5="fail"; log_event "pin5" "failed" "rc=${rc} class=${kclass}"
    fi
  else
    log_event "pin5" "skipped" "docker unavailable; clean-room path not exercised this run"
    echo "[${COMPONENT}] PIN 5 docker clean-room : SKIP (docker unavailable)"
  fi

  rm -rf "${work}"

  # PIN 5 is advisory-when-skipped: it must not be 'fail'. Required pins are 1-4.
  [[ "${pin1}" == "pass" && "${pin2}" == "pass" && "${pin3}" == "pass" && "${pin4}" == "pass" ]] || overall="fail"
  [[ "${pin5}" == "fail" ]] && overall="fail"

  {
    echo "Y.4 operator proof-bundle surface gate — ${BEAD_ID}"
    echo "PIN 1 round-trip verify       : ${pin1}"
    echo "PIN 2 tamper fail-closed      : ${pin2}"
    echo "PIN 3 drift != regression     : ${pin3}"
    echo "PIN 4 anti-drift constants/doc: ${pin4}"
    echo "PIN 5 docker clean-room       : ${pin5}"
    echo "verdict                       : ${overall}"
  } >"${RUN_DIR}/summary.txt"
  cat "${RUN_DIR}/summary.txt"

  write_manifest "${overall}" "pin1=${pin1}" "pin2=${pin2}" "pin3=${pin3}" "pin4=${pin4}" "pin5=${pin5}"
  log_event "gate" "${overall}" "pin1=${pin1} pin2=${pin2} pin3=${pin3} pin4=${pin4} pin5=${pin5}"
  echo "[${COMPONENT}] artifacts: ${RUN_DIR#"${ROOT_DIR}"/}"
  [[ "${overall}" == "pass" ]] && return 0 || return 1
}

# PIN 4a: the wrapper's pinned Y.2 image + build-gate strings must equal the
# Rust canonical constants (single source of truth, anti-drift).
assert_constants_agree() {
  local wrap_image wrap_gate rust_image rust_gate y2_bead
  wrap_image="$(grep -oE 'Y2_IMAGE_TAG="[^"]+"' "${ROOT_DIR}/${WRAPPER}" | head -n1 | sed 's/.*="//; s/"$//')"
  wrap_gate="$(grep -oE 'Y2_BUILD_GATE="[^"]+"' "${ROOT_DIR}/${WRAPPER}" | head -n1 | sed 's/.*="//; s/"$//')"
  rust_image="$(grep -oE '"frankenengine/y2-proof-bundle-verifier:[^"]+"' "${ROOT_DIR}/${RUST_CONSTS}" | head -n1 | tr -d '"')"
  rust_gate="$(grep -oE '"scripts/run_y2_proof_bundle_verifier.sh"' "${ROOT_DIR}/${RUST_CONSTS}" | head -n1 | tr -d '"')"
  y2_bead="$(grep -oE 'BEAD_ID="bd-cixqu\.25\.2"' "${ROOT_DIR}/${Y2_GATE}" | head -n1)"
  [[ -n "${wrap_image}" && "${wrap_image}" == "${rust_image}" ]] \
    || { echo "[${COMPONENT}] constant drift: wrapper image ${wrap_image} != rust ${rust_image}" >&2; return 1; }
  [[ -n "${wrap_gate}" && "${wrap_gate}" == "${rust_gate}" ]] \
    || { echo "[${COMPONENT}] constant drift: wrapper gate ${wrap_gate} != rust ${rust_gate}" >&2; return 1; }
  [[ -n "${y2_bead}" ]] \
    || { echo "[${COMPONENT}] Y.2 gate does not pin bead bd-cixqu.25.2" >&2; return 1; }
  return 0
}

# PIN 4b: every repo path the public doc references must resolve to a real file.
assert_doc_resolves() {
  [[ -f "${ROOT_DIR}/${PUBLIC_DOC}" ]] || { echo "[${COMPONENT}] missing ${PUBLIC_DOC}" >&2; return 1; }
  local refs=(
    "runbooks/scripts/verify_proof_bundle.sh"
    "scripts/export_proof_bundle.sh"
    "scripts/run_y2_proof_bundle_verifier.sh"
    "scripts/run_y4_proof_bundle_operator_surface.sh"
    "docker/y2_proof_bundle_verifier/verify_proof_bundle.py"
    "crates/franken-engine/src/proof_bundle_status_panel.rs"
    "crates/franken-engine/src/ga_exit_evidence_package.rs"
    "docs/adr/ADR-0007-proof-assistant-selection.md"
  )
  local p ok=0
  for p in "${refs[@]}"; do
    if ! grep -q "${p}" "${ROOT_DIR}/${PUBLIC_DOC}"; then
      echo "[${COMPONENT}] doc does not reference ${p}" >&2; ok=1
    fi
    if [[ ! -e "${ROOT_DIR}/${p}" ]]; then
      echo "[${COMPONENT}] doc-referenced path missing on disk: ${p}" >&2; ok=1
    fi
  done
  return "${ok}"
}

main() {
  local mode="${1:-ci}"
  case "${mode}" in
    -h|--help) usage; exit 0 ;;
    ci|gate) run_ci ;;
    *) echo "unknown mode: ${mode}" >&2; usage; exit 2 ;;
  esac
}

main "$@"
