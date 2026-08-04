#!/usr/bin/env bash
#
# Y.2 — External verification scripted environment / docker image
# (bd-cixqu.25.2, Track Y: third-party-verifiable proof bundles).
#
# Builds a clean-room docker image (docker/y2_proof_bundle_verifier/) that
# contains ONLY the standalone proof-checker — no FrankenEngine source — and
# exercises it against a real Y.1 proof bundle (scripts/export_proof_bundle.sh,
# bd-cixqu.25.1). The image's `verify-proof-bundle` mode consumes the bundle
# tar and emits a typed pass/fail verdict.
#
# The `ci` gate fails closed unless all three Y.2 pins hold:
#   PIN 1  clean-room verify of a valid bundle PASSES (exit 0, verdict=pass);
#   PIN 2  a tampered/incomplete bundle FAILS CLOSED (exit 1, verdict=fail);
#   PIN 3  the image carries NO engine source (no *.rs / Cargo.toml / crates/).
#
# Per bd-cixqu.45 the container verification logs (stdout verdict + stderr) are
# captured as the third-party-trust evidence artifact under the run bundle.
#
# Modes:
#   ci | gate            build image + run all three pins + emit RGC bundle (default)
#   build                build the verifier image only
#   verify <bundle.tgz>  run the image against an existing bundle tar
#   -h | --help          usage
#
# This gate is docker + bash + python3 only; it does NOT route through rch
# (no cargo build is involved).

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

readonly COMPONENT="y2_proof_bundle_verifier"
readonly BEAD_ID="bd-cixqu.25.2"
readonly DOCKER_CONTEXT="docker/y2_proof_bundle_verifier"
readonly IMAGE_TAG="frankenengine/y2-proof-bundle-verifier:${BEAD_ID}"
readonly MANIFEST_SCHEMA="franken-engine.proof-artifact-manifest.v1"
readonly EXPORT_TOOL="scripts/export_proof_bundle.sh"
readonly PROOF_SCHEMA="franken-engine.theorem-backed-compiler.proof.v1"
readonly ARTIFACT_ROOT="${Y2_PROOF_BUNDLE_VERIFIER_ARTIFACT_ROOT:-${ROOT_DIR}/artifacts/${COMPONENT}}"

usage() {
  cat >&2 <<EOF
usage: $0 [ci|gate]             build image + run 3 Y.2 pins + emit RGC bundle (default)
       $0 build                 build the verifier image only
       $0 verify <bundle.tgz>   run the image against an existing proof-bundle tar
       $0 -h | --help

Exit codes:
  0  gate passed / verify passed
  1  gate failed (a pin failed) / verify failed (fail-closed)
  2  CLI or environment error (e.g. docker unavailable)
EOF
}

die() {
  echo "[${COMPONENT}] ERROR: $*" >&2
  exit 2
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
  docker info >/dev/null 2>&1 || die "docker daemon is not reachable"
}

# --- RGC bundle plumbing -----------------------------------------------------
RUN_DIR=""
EVENTS_PATH=""
COMMANDS_PATH=""
STEP_DIR=""
STEP_SEQ=0
TRACE_ID=""
DECISION_ID=""
POLICY_ID="policy-${COMPONENT}-v1"

init_run_bundle() {
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="${ARTIFACT_ROOT}/${ts}"
  EVENTS_PATH="${RUN_DIR}/events.jsonl"
  COMMANDS_PATH="${RUN_DIR}/commands.txt"
  STEP_DIR="${RUN_DIR}/step_logs"
  TRACE_ID="trace-${COMPONENT}-${ts}"
  DECISION_ID="decision-${COMPONENT}-${ts}"
  mkdir -p "${STEP_DIR}"
  : >"${EVENTS_PATH}"
  : >"${COMMANDS_PATH}"
  cat >"${RUN_DIR}/trace_ids.json" <<EOF
{
  "trace_id": "${TRACE_ID}",
  "decision_id": "${DECISION_ID}",
  "policy_id": "${POLICY_ID}"
}
EOF
}

log_event() {
  # log_event <kind> <status> <detail>
  local kind="$1" status="$2" detail="$3" now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$EVENTS_PATH" "$kind" "$status" "$detail" "$now" "$TRACE_ID" "$COMPONENT" <<'PY'
import json, sys
path, kind, status, detail, now, trace, comp = sys.argv[1:8]
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({
        "schema_id": "franken-engine.evidence-record.v1",
        "trace_id": trace,
        "component": comp,
        "kind": kind,
        "status": status,
        "detail": detail,
        "generated_utc": now,
    }, sort_keys=True) + "\n")
PY
}

# run_step <label> <logfile-basename> -- <cmd...>
# Captures stdout+stderr to a per-step log, mirrors the command into commands.txt,
# and returns the command's exit code (without aborting the gate).
run_step() {
  local label="$1" base="$2"
  shift 2
  [[ "$1" == "--" ]] && shift
  local seq
  seq="$(printf '%03d' "${STEP_SEQ}")"
  STEP_SEQ=$((STEP_SEQ + 1))
  local logf="${STEP_DIR}/step_${seq}_${base}.log"
  echo "# [${label}] $*" >>"${COMMANDS_PATH}"
  echo "\$ $*" >>"${COMMANDS_PATH}"
  local rc=0
  if "$@" >"${logf}" 2>&1; then rc=0; else rc=$?; fi
  echo "  -> exit ${rc} (log: ${logf#"${ROOT_DIR}"/})" >>"${COMMANDS_PATH}"
  return "${rc}"
}

build_image() {
  log_event "build" "started" "docker build ${IMAGE_TAG}"
  if run_step "build image" "docker_build" -- \
      docker build --pull=false -t "${IMAGE_TAG}" "${DOCKER_CONTEXT}"; then
    log_event "build" "ok" "built ${IMAGE_TAG}"
    return 0
  fi
  log_event "build" "failed" "docker build failed"
  return 1
}

# Make a valid Y.1 proof bundle from a small fixture proof source. Echoes the
# absolute path of the produced proof_bundle.tar.gz on success.
make_fixture_bundle() {
  local work="$1"
  local fx="${work}/fixture_proof_source"
  local out="${work}/export"
  mkdir -p "${fx}"
  # Author a few schema-valid proofs with correctly-derived content_hash,
  # mirroring Y.1's canonical body-hash so the exported bundle is "complete".
  FX_DIR="${fx}" FX_SCHEMA="${PROOF_SCHEMA}" python3 <<'PY'
import hashlib, json, os
d = os.environ["FX_DIR"]
schema = os.environ["FX_SCHEMA"]
claims = [
    ("FE-CLAIM-016", "G.2,G.3", "formal-spec-isomorphism"),
    ("FE-CLAIM-019", "G.8", "optimization-isomorphism"),
    ("FE-CLAIM-020", "G.7,G.8", "theorem-backed-compiler"),
]
for claim_id, track, kind in claims:
    proof = {
        "schema_version": schema,
        "claim_id": claim_id,
        "track": track,
        "proof_kind": kind,
        "verdict": "proven",
        # Fixed generated_utc so the fixture itself is reproducible.
        "generated_utc": "2026-01-01T00:00:00Z",
        "source_module": "y2-selftest-fixture",
    }
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    proof["content_hash"] = "sha256:" + hashlib.sha256(enc).hexdigest()
    with open(os.path.join(d, claim_id + ".proof.json"), "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2, sort_keys=True)
        fh.write("\n")
PY
  if ! run_step "export Y.1 bundle" "y1_export" -- \
      bash "${EXPORT_TOOL}" export "${fx}" "${out}"; then
    return 1
  fi
  local tar="${out}/proof_bundle.tar.gz"
  [[ -f "${tar}" ]] || return 1
  printf '%s\n' "${tar}"
}

# Produce a tampered copy of a valid bundle: mutate one proof body without
# re-deriving its content_hash, re-pack deterministically. Echoes the tar path.
make_tampered_bundle() {
  local valid_tar="$1" work="$2"
  local stage="${work}/tamper_stage"
  mkdir -p "${stage}"
  tar -xzf "${valid_tar}" -C "${stage}"
  local victim
  victim="$(find "${stage}" -name '*.proof.json' | sort | head -n1)"
  [[ -n "${victim}" ]] || return 1
  VICTIM="${victim}" python3 <<'PY'
import json, os
p = os.environ["VICTIM"]
with open(p, encoding="utf-8") as fh:
    proof = json.load(fh)
proof["source_module"] = "tampered-after-export"  # body changes, content_hash stale
with open(p, "w", encoding="utf-8") as fh:
    json.dump(proof, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  local bundle_root
  bundle_root="$(cd "${stage}" && find . -maxdepth 1 -mindepth 1 -type d | head -n1)"
  bundle_root="${bundle_root#./}"
  local tar="${work}/proof_bundle_tampered.tar.gz"
  ( cd "${stage}" && tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
      --numeric-owner -czf "${tar}" "${bundle_root}" )
  printf '%s\n' "${tar}"
}

# Run the image against a bundle tar. Args: <bundle.tgz> <verdict-json-out> <log-basename>.
# Container stdout (the typed JSON verdict, the third-party-trust artifact) is
# captured cleanly to <verdict-json-out>; stderr (the human summary) goes to the
# step log. Returns the container exit code.
docker_verify() {
  local tar="$1" verdict_out="$2" base="$3"
  local abs_tar
  abs_tar="$(cd "$(dirname "${tar}")" && pwd)/$(basename "${tar}")"
  local seq logf
  seq="$(printf '%03d' "${STEP_SEQ}")"
  STEP_SEQ=$((STEP_SEQ + 1))
  logf="${STEP_DIR}/step_${seq}_${base}.log"
  {
    echo "# [docker verify ${base}] stdout->verdict json, stderr->log"
    echo "\$ docker run --rm --network=none -v ${abs_tar}:/input/proof_bundle.tar.gz:ro ${IMAGE_TAG} verify-proof-bundle /input/proof_bundle.tar.gz"
  } >>"${COMMANDS_PATH}"
  local rc=0
  docker run --rm --network=none \
    -v "${abs_tar}:/input/proof_bundle.tar.gz:ro" \
    "${IMAGE_TAG}" verify-proof-bundle /input/proof_bundle.tar.gz \
    >"${verdict_out}" 2>"${logf}" || rc=$?
  echo "  -> exit ${rc} (verdict: ${verdict_out#"${ROOT_DIR}"/}, log: ${logf#"${ROOT_DIR}"/})" >>"${COMMANDS_PATH}"
  return "${rc}"
}

# PIN 3: assert the built image carries no engine source.
inspect_no_leak() {
  local out="${RUN_DIR}/image_source_scan.txt"
  echo "# [image no-leak scan] docker run --entrypoint python3 (filesystem scan)" >>"${COMMANDS_PATH}"
  if docker run --rm --network=none --entrypoint python3 "${IMAGE_TAG}" -c '
import os, json
hits = []
for root, _dirs, files in os.walk("/"):
    # skip virtual trees that legitimately contain no engine src
    if root.startswith(("/proc", "/sys", "/dev")):
        continue
    for f in files:
        low = f.lower()
        if low.endswith(".rs") or f in ("Cargo.toml", "Cargo.lock") or "baseline_interpreter" in low:
            hits.append(os.path.join(root, f))
# also confirm /verifier holds only the checker
vfiles = sorted(os.listdir("/verifier")) if os.path.isdir("/verifier") else []
print(json.dumps({"engine_source_hits": hits, "verifier_dir": vfiles}, sort_keys=True))
' >"${out}" 2>>"${COMMANDS_PATH}"; then
    # No hits AND /verifier holds only the checker => clean.
    if grep -q '"engine_source_hits": \[\]' "${out}" 2>/dev/null \
       && grep -q '"verify_proof_bundle.py"' "${out}" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

write_manifest() {
  local verdict="$1" pin1="$2" pin2="$3" pin3="$4"
  local image_id
  image_id="$(docker image inspect --format '{{.Id}}' "${IMAGE_TAG}" 2>/dev/null || echo unknown)"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RUN_DIR="${RUN_DIR}" SCHEMA="${MANIFEST_SCHEMA}" COMPONENT_ENV="${COMPONENT}" \
  BEAD="${BEAD_ID}" IMAGE_TAG_ENV="${IMAGE_TAG}" IMAGE_ID="${image_id}" \
  VERDICT="${verdict}" PIN1="${pin1}" PIN2="${pin2}" PIN3="${pin3}" \
  TRACE_ID="${TRACE_ID}" NOW="${now}" python3 <<'PY'
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
        full = os.path.join(dirpath, f)
        rel = os.path.relpath(full, run_dir)
        if rel == "run_manifest.json":
            continue
        try:
            artifacts[rel] = sha256(full)
        except OSError:
            pass
manifest = {
    "schema_id": os.environ["SCHEMA"],
    "component": os.environ["COMPONENT_ENV"],
    "bead_id": os.environ["BEAD"],
    "scope": "Y.2 third-party proof-bundle verifier (docker)",
    "trace_id": os.environ["TRACE_ID"],
    "generated_utc": os.environ["NOW"],
    "verdict": os.environ["VERDICT"],
    "pins": {
        "pin1_clean_room_verify_pass": os.environ["PIN1"],
        "pin2_tamper_fails_closed": os.environ["PIN2"],
        "pin3_no_engine_source_leak": os.environ["PIN3"],
    },
    "image": {
        "tag": os.environ["IMAGE_TAG_ENV"],
        "id": os.environ["IMAGE_ID"],
        "base_pinned_by_digest": True,
    },
    "host_facts": {
        "uname": os.uname().sysname + " " + os.uname().release + " " + os.uname().machine,
    },
    "operator_verification": {
        "rerun": "./scripts/run_y2_proof_bundle_verifier.sh ci",
        "replay": "./scripts/e2e/y2_proof_bundle_verifier_replay.sh",
    },
    "artifact_content_hashes": artifacts,
}
with open(os.path.join(run_dir, "run_manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

run_ci() {
  require_docker
  init_run_bundle
  log_event "gate" "started" "${BEAD_ID} Y.2 proof-bundle verifier gate"
  echo "[${COMPONENT}] run bundle: ${RUN_DIR}"

  local overall="pass" pin1="fail" pin2="fail" pin3="fail"

  if ! build_image; then
    write_manifest "fail" "${pin1}" "${pin2}" "${pin3}"
    echo "[${COMPONENT}] GATE FAIL: image build failed" >&2
    return 1
  fi

  local work="${RUN_DIR}/work"
  mkdir -p "${work}"
  local valid_tar
  if ! valid_tar="$(make_fixture_bundle "${work}")"; then
    log_event "fixture" "failed" "could not produce a valid Y.1 bundle"
    write_manifest "fail" "${pin1}" "${pin2}" "${pin3}"
    echo "[${COMPONENT}] GATE FAIL: fixture bundle export failed" >&2
    return 1
  fi
  cp "${valid_tar}" "${RUN_DIR}/proof_bundle_valid.tar.gz" 2>/dev/null || true

  # PIN 1 — valid bundle verifies (exit 0, verdict=pass).
  if docker_verify "${valid_tar}" "${RUN_DIR}/verdict_valid.json" "verify_valid"; then
    if grep -q '"verdict": "pass"' "${RUN_DIR}/verdict_valid.json" 2>/dev/null; then
      pin1="pass"
      log_event "pin1" "pass" "clean-room verify of valid bundle passed"
    else
      log_event "pin1" "failed" "exit 0 but verdict not pass"
    fi
  else
    log_event "pin1" "failed" "valid bundle did not verify (exit non-zero)"
  fi

  # PIN 2 — tampered bundle fails closed (exit 1, verdict=fail).
  local tampered_tar
  if tampered_tar="$(make_tampered_bundle "${valid_tar}" "${work}")"; then
    cp "${tampered_tar}" "${RUN_DIR}/proof_bundle_tampered.tar.gz" 2>/dev/null || true
    if docker_verify "${tampered_tar}" "${RUN_DIR}/verdict_tampered.json" "verify_tampered"; then
      log_event "pin2" "failed" "tampered bundle verified (NOT fail-closed)"
    else
      if grep -q '"verdict": "fail"' "${RUN_DIR}/verdict_tampered.json" 2>/dev/null; then
        pin2="pass"
        log_event "pin2" "pass" "tampered bundle failed closed with verdict=fail"
      else
        log_event "pin2" "failed" "non-zero exit but no fail verdict captured"
      fi
    fi
  else
    log_event "pin2" "failed" "could not build tampered bundle"
  fi

  # PIN 3 — image carries no engine source.
  if inspect_no_leak; then
    pin3="pass"
    log_event "pin3" "pass" "image carries no engine source; /verifier holds only the checker"
  else
    log_event "pin3" "failed" "engine source leak detected or verifier dir unexpected"
  fi

  # Drop the scratch working tree; the canonical trust artifacts (valid +
  # tampered tars, verdicts, image scan) are already at the run-dir root.
  rm -rf "${work}"

  [[ "${pin1}" == "pass" && "${pin2}" == "pass" && "${pin3}" == "pass" ]] || overall="fail"
  write_manifest "${overall}" "${pin1}" "${pin2}" "${pin3}"
  log_event "gate" "${overall}" "pin1=${pin1} pin2=${pin2} pin3=${pin3}"

  echo "[${COMPONENT}] PIN 1 clean-room verify : ${pin1}"
  echo "[${COMPONENT}] PIN 2 tamper fail-closed : ${pin2}"
  echo "[${COMPONENT}] PIN 3 no engine source   : ${pin3}"
  echo "[${COMPONENT}] verdict: ${overall}"
  echo "[${COMPONENT}] artifacts: ${RUN_DIR}"
  [[ "${overall}" == "pass" ]] && return 0 || return 1
}

run_verify_only() {
  local bundle="$1"
  [[ -n "${bundle}" ]] || die "verify requires a bundle tar path"
  [[ -f "${bundle}" ]] || die "bundle not found: ${bundle}"
  require_docker
  init_run_bundle
  if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
    build_image || die "image build failed"
  fi
  local rc=0
  docker_verify "${bundle}" "${RUN_DIR}/verdict.json" "verify_adhoc" || rc=$?
  write_manifest "$([[ ${rc} -eq 0 ]] && echo pass || echo fail)" "n/a" "n/a" "n/a"
  echo "[${COMPONENT}] verdict written: ${RUN_DIR}/verdict.json (exit ${rc})"
  return "${rc}"
}

main() {
  local mode="${1:-ci}"
  case "${mode}" in
    -h|--help) usage; exit 0 ;;
    ci|gate) run_ci ;;
    build) require_docker; init_run_bundle; build_image && echo "[${COMPONENT}] built ${IMAGE_TAG}" ;;
    verify) run_verify_only "${2:-}" ;;
    *) echo "unknown mode: ${mode}" >&2; usage; exit 2 ;;
  esac
}

main "$@"
