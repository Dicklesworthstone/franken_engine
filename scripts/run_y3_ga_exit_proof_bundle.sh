#!/usr/bin/env bash
#
# Y.3 — Integrate the third-party proof bundle into the GA-exit evidence package
# (bd-cixqu.25.3, Track Y).
#
# This gate proves the three Track-Y surfaces compose and cannot drift:
#   Y.1  scripts/export_proof_bundle.sh        (produces proof_bundle.tar.gz)
#   Y.2  scripts/run_y2_proof_bundle_verifier  (clean-room docker verifier)
#   Y.3  ga_exit_evidence_package.rs           (ProofBundleReference wiring)
#
# Pins (fail-closed):
#   PIN 1  cross-track constant agreement: the proof-bundle schema and Y.2
#          verifier image strings are identical across the Rust package module,
#          the Y.1 exporter, and the Y.2 verifier gate (the "single constant"
#          anti-drift contract).
#   PIN 2  end-to-end round-trip: export a real Y.1 bundle and re-check it with
#          the Y.2 verifier; the verdict is pass and the digest the GA package
#          would record (bundle_manifest.recheck_digest_sha256) equals the digest
#          the Y.2 verifier independently recomputes.
#   PIN 3  README GA-exit section names the proof bundle as a third-party trust
#          artifact and its reproduce commands resolve to real scripts.
#
# Per bd-cixqu.45 the assembled package-reference manifest and the verify
# round-trip log are captured as evidence under the run bundle.
#
# Modes: ci|gate (default), -h|--help. docker + bash + python3 + jq only.

set -euo pipefail
export TZ=UTC LC_ALL=C LANG=C LANGUAGE=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly COMPONENT="y3_ga_exit_proof_bundle"
readonly BEAD_ID="bd-cixqu.25.3"
readonly PKG_RS="crates/franken-engine/src/ga_exit_evidence_package.rs"
readonly Y1_EXPORT="scripts/export_proof_bundle.sh"
readonly Y2_GATE="scripts/run_y2_proof_bundle_verifier.sh"
readonly MANIFEST_SCHEMA="franken-engine.proof-artifact-manifest.v1"
readonly ARTIFACT_ROOT="${Y3_GA_EXIT_PROOF_BUNDLE_ARTIFACT_ROOT:-${ROOT_DIR}/artifacts/${COMPONENT}}"

usage() {
  cat >&2 <<EOF
usage: $0 [ci|gate]   run the 3 Y.3 pins + emit RGC bundle (default)
       $0 -h | --help

Exit codes: 0 gate passed, 1 a pin failed, 2 environment error.
EOF
}

die() { echo "[${COMPONENT}] ERROR: $*" >&2; exit 2; }

RUN_DIR=""
EVENTS_PATH=""
COMMANDS_PATH=""
STEP_DIR=""
TRACE_ID=""

init_run_bundle() {
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="${ARTIFACT_ROOT}/${ts}"
  EVENTS_PATH="${RUN_DIR}/events.jsonl"
  COMMANDS_PATH="${RUN_DIR}/commands.txt"
  STEP_DIR="${RUN_DIR}/step_logs"
  TRACE_ID="trace-${COMPONENT}-${ts}"
  mkdir -p "${STEP_DIR}"
  : >"${EVENTS_PATH}"
  : >"${COMMANDS_PATH}"
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

# Extract the first quoted string value at/after a constant declaration. The
# value may sit on the same line or the next (rustfmt wraps long const lines).
const_value() {
  local file="$1" name="$2"
  grep -A1 -E "${name}" "$file" 2>/dev/null | grep -oE '"[^"]+"' | head -n1 | sed -E 's/^"(.*)"$/\1/'
}

# PIN 1 — cross-track constant agreement.
pin_constant_agreement() {
  local out="${RUN_DIR}/constant_agreement.json"
  local rs_schema rs_image y1_schema y2_bead y2_image
  rs_schema="$(const_value "${PKG_RS}" 'PROOF_BUNDLE_SCHEMA_VERSION: &str')"
  rs_image="$(const_value "${PKG_RS}" 'PROOF_BUNDLE_VERIFIER_IMAGE: &str')"
  y1_schema="$(const_value "${Y1_EXPORT}" '^readonly BUNDLE_SCHEMA=')"
  # Y.2 image tag is built from IMAGE_TAG="frankenengine/...:${BEAD_ID}".
  y2_bead="$(const_value "${Y2_GATE}" 'BEAD_ID=')"
  y2_image="$(grep -oE 'IMAGE_TAG="[^"]+"' "${Y2_GATE}" | head -n1 | sed -E 's/.*"([^"]+)"/\1/' | sed "s/\${BEAD_ID}/${y2_bead}/")"
  python3 - "$out" "$rs_schema" "$rs_image" "$y1_schema" "$y2_image" <<'PY'
import json, sys
out, rs_schema, rs_image, y1_schema, y2_image = sys.argv[1:6]
schema_ok = rs_schema and rs_schema == y1_schema
image_ok = rs_image and rs_image == y2_image
data = {"rs_schema": rs_schema, "y1_schema": y1_schema, "schema_agree": schema_ok,
        "rs_verifier_image": rs_image, "y2_image": y2_image, "image_agree": image_ok}
open(out, "w").write(json.dumps(data, indent=2, sort_keys=True) + "\n")
sys.exit(0 if (schema_ok and image_ok) else 1)
PY
}

# PIN 2 — end-to-end round-trip through the Y.2 verifier.
pin_round_trip() {
  local work="${RUN_DIR}/work"
  local fx="${work}/fixture_proof_source" out="${work}/export"
  mkdir -p "${fx}"
  FX_DIR="${fx}" python3 <<'PY'
import hashlib, json, os
d = os.environ["FX_DIR"]
schema = "franken-engine.theorem-backed-compiler.proof.v1"
for claim_id, track, kind in [
    ("FE-CLAIM-016", "G.2,G.3", "formal-spec-isomorphism"),
    ("FE-CLAIM-020", "G.7,G.8", "theorem-backed-compiler"),
]:
    proof = {"schema_version": schema, "claim_id": claim_id, "track": track,
             "proof_kind": kind, "verdict": "proven",
             "generated_utc": "2026-01-01T00:00:00Z", "source_module": "y3-fixture"}
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    proof["content_hash"] = "sha256:" + hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with open(os.path.join(d, claim_id + ".proof.json"), "w") as fh:
        json.dump(proof, fh, indent=2, sort_keys=True); fh.write("\n")
PY
  echo "\$ ${Y1_EXPORT} export ${fx} ${out}" >>"${COMMANDS_PATH}"
  bash "${Y1_EXPORT}" export "${fx}" "${out}" >"${STEP_DIR}/y1_export.log" 2>&1 || return 1
  local tar="${out}/proof_bundle.tar.gz"
  [[ -f "${tar}" ]] || return 1
  cp "${tar}" "${RUN_DIR}/proof_bundle.tar.gz"
  # digest the GA package would record (from the bundle manifest).
  local pkg_digest
  pkg_digest="$(jq -r '.recheck_digest_sha256' "${out}/bundle/bundle_manifest.json")"
  # round-trip through the Y.2 verifier.
  echo "\$ ${Y2_GATE} verify ${tar}" >>"${COMMANDS_PATH}"
  if ! bash "${Y2_GATE}" verify "${tar}" >"${STEP_DIR}/y2_verify.log" 2>&1; then
    return 1
  fi
  # find the Y.2 verdict json and confirm pass + digest equality with the GA ref.
  local verdict
  verdict="$(find artifacts/y2_proof_bundle_verifier -name verdict.json -newermt '-3 minutes' 2>/dev/null | LC_ALL=C sort -r | head -n1)"
  [[ -n "${verdict}" && -f "${verdict}" ]] || return 1
  cp "${verdict}" "${RUN_DIR}/y2_verdict.json"
  local v_verdict v_digest
  v_verdict="$(jq -r '.verdict' "${verdict}")"
  v_digest="$(jq -r '.recomputed_recheck_digest' "${verdict}")"
  python3 - "${RUN_DIR}/round_trip.json" "${pkg_digest}" "${v_digest}" "${v_verdict}" "${tar}" <<'PY'
import json, sys, os
out, pkg_digest, v_digest, v_verdict, tar = sys.argv[1:6]
ok = (v_verdict == "pass") and pkg_digest and (pkg_digest == v_digest)
data = {"ga_package_recorded_digest": pkg_digest, "y2_recomputed_digest": v_digest,
        "digests_agree": pkg_digest == v_digest, "y2_verdict": v_verdict,
        "bundle": os.path.basename(tar)}
open(out, "w").write(json.dumps(data, indent=2, sort_keys=True) + "\n")
sys.exit(0 if ok else 1)
PY
}

# PIN 3 — README GA-exit section names the surface + reproduce commands resolve.
pin_readme() {
  local out="${RUN_DIR}/readme_check.txt"
  local ok=1
  : >"${out}"
  for needle in "third-party-verifiable proof bundle" \
                "scripts/export_proof_bundle.sh" \
                "scripts/run_y2_proof_bundle_verifier.sh"; do
    if grep -qF "${needle}" README.md; then
      echo "OK   README contains: ${needle}" >>"${out}"
    else
      echo "MISS README missing: ${needle}" >>"${out}"
      ok=0
    fi
  done
  # the referenced scripts must actually exist + be executable.
  for s in "${Y1_EXPORT}" "${Y2_GATE}"; do
    if [[ -x "${s}" ]]; then echo "OK   resolves: ${s}" >>"${out}"; else echo "MISS not executable: ${s}" >>"${out}"; ok=0; fi
  done
  [[ "${ok}" -eq 1 ]]
}

write_manifest() {
  local verdict="$1" p1="$2" p2="$3" p3="$4" now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RUN_DIR="${RUN_DIR}" SCHEMA="${MANIFEST_SCHEMA}" COMP="${COMPONENT}" BEAD="${BEAD_ID}" \
  VERDICT="${verdict}" P1="${p1}" P2="${p2}" P3="${p3}" TRACE="${TRACE_ID}" NOW="${now}" \
  python3 <<'PY'
import hashlib, json, os
run_dir = os.environ["RUN_DIR"]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(65536), b""): h.update(c)
    return "sha256:" + h.hexdigest()
arts = {}
for dp, _d, files in os.walk(run_dir):
    for f in files:
        full = os.path.join(dp, f); rel = os.path.relpath(full, run_dir)
        if rel == "run_manifest.json": continue
        try: arts[rel] = sha(full)
        except OSError: pass
m = {"schema_id": os.environ["SCHEMA"], "component": os.environ["COMP"],
     "bead_id": os.environ["BEAD"], "scope": "Y.3 GA-exit proof-bundle integration",
     "trace_id": os.environ["TRACE"], "generated_utc": os.environ["NOW"],
     "verdict": os.environ["VERDICT"],
     "pins": {"pin1_constant_agreement": os.environ["P1"],
              "pin2_round_trip_through_y2": os.environ["P2"],
              "pin3_readme_link_resolves": os.environ["P3"]},
     "operator_verification": {"rerun": "./scripts/run_y3_ga_exit_proof_bundle.sh ci"},
     "artifact_content_hashes": arts}
open(os.path.join(run_dir, "run_manifest.json"), "w").write(json.dumps(m, indent=2, sort_keys=True) + "\n")
PY
}

run_ci() {
  command -v docker >/dev/null 2>&1 || die "docker not found"
  docker info >/dev/null 2>&1 || die "docker daemon unreachable"
  command -v jq >/dev/null 2>&1 || die "jq not found"
  init_run_bundle
  log_event "gate" "started" "${BEAD_ID} Y.3 GA-exit proof-bundle integration"
  echo "[${COMPONENT}] run bundle: ${RUN_DIR}"

  local p1="fail" p2="fail" p3="fail" overall="pass"
  if pin_constant_agreement; then p1="pass"; log_event "pin1" "pass" "constants agree across Rust/Y.1/Y.2"; else log_event "pin1" "failed" "cross-track constant drift"; fi
  if pin_round_trip; then p2="pass"; log_event "pin2" "pass" "Y.1 bundle round-trips through Y.2 verifier; digests agree"; else log_event "pin2" "failed" "round-trip through Y.2 failed"; fi
  if pin_readme; then p3="pass"; log_event "pin3" "pass" "README names surface + reproduce commands resolve"; else log_event "pin3" "failed" "README link/needle missing"; fi

  rm -rf "${RUN_DIR}/work"
  [[ "${p1}" == "pass" && "${p2}" == "pass" && "${p3}" == "pass" ]] || overall="fail"
  write_manifest "${overall}" "${p1}" "${p2}" "${p3}"
  log_event "gate" "${overall}" "pin1=${p1} pin2=${p2} pin3=${p3}"
  echo "[${COMPONENT}] PIN 1 constant agreement : ${p1}"
  echo "[${COMPONENT}] PIN 2 round-trip via Y.2  : ${p2}"
  echo "[${COMPONENT}] PIN 3 README link resolves: ${p3}"
  echo "[${COMPONENT}] verdict: ${overall}"
  echo "[${COMPONENT}] artifacts: ${RUN_DIR}"
  [[ "${overall}" == "pass" ]] && return 0 || return 1
}

main() {
  case "${1:-ci}" in
    -h|--help) usage; exit 0 ;;
    ci|gate) run_ci ;;
    *) echo "unknown mode: ${1}" >&2; usage; exit 2 ;;
  esac
}

main "$@"
