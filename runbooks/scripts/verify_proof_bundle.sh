#!/usr/bin/env bash
#
# verify_proof_bundle.sh — operator / downstream-consumer proof-bundle verifier
#
# Track Y, bead bd-cixqu.25.4 (Y.4 operator surface). This is the friendly,
# operator-facing wrapper around the *single source of truth* proof-checker
# `docker/y2_proof_bundle_verifier/verify_proof_bundle.py` (Y.2). It re-checks a
# release proof bundle (`proof_bundle.tar.gz`, exported by Y.1
# `scripts/export_proof_bundle.sh`) and classifies the outcome so an operator
# knows *what to do next*.
#
# It runs the checker one of two ways (both re-implement nothing — they invoke
# the same Y.2 checker so the trust path can never drift):
#
#   --via docker   run inside the Y.2 clean-room image (strongest: no engine
#                  source on the host is consulted);
#   --via local    run the checker directly with the host python3 (no docker
#                  required — handy on a laptop);
#   --via auto     (default) docker when a tar bundle + reachable daemon are
#                  present, else local.
#
# The Y.2 checker verifies the bundle's *recheck digest* — a pure function of the
# proof-source bytes, INDEPENDENT of the proof-assistant version. So this wrapper
# also reports a second, ORTHOGONAL dimension the checker does not: whether the
# operator's installed proof assistant (Lean 4 / Coq) drifts from the bundle's
# pinned versions (`proof_assistant_versions.json`). Because the two dimensions
# are independent, the wrapper can cleanly separate:
#
#   * proof_regression  — the recheck digest no longer reproduces the trust
#                         anchor (a proof body/verdict changed, or the bundle is
#                         incomplete). The release is NOT verified. ESCALATE to
#                         the FrankenEngine maintainers.
#   * version_drift     — the recheck still holds, but the operator's toolchain
#                         differs from the bundle's pinned proof-assistant
#                         versions. Advisory: UPDATE the local toolchain before
#                         re-running the underlying Lean/Coq proofs.
#   * verified          — recheck digest matches the trust anchor and the
#                         toolchain is aligned or absent. Safe to rely on.
#
# Per bd-cixqu.45 logging discipline: every run writes a content-addressed bundle
# under artifacts/proof_bundle_operator_verify/<UTC-ts>/ with events.jsonl,
# commands.txt, the classified operator verdict, the raw Y.2 verdict, and a
# run_manifest.json carrying per-artifact sha256 + operator-verification commands.
#
# Modes:
#   verify <bundle.tar.gz|bundle-dir> [flags]   classify a target bundle
#   selftest                                    fixture-driven proof of all three
#                                               classifications (no engine build)
#   -h | --help                                 usage
#
# Flags (verify):
#   --via docker|local|auto      checker execution path (default auto)
#   --expected-lean <ver>        operator-expected Lean pin the bundle SHOULD
#                                carry; mismatch => version_drift(expected_mismatch)
#   --expected-coq  <ver>        operator-expected Coq pin (as above)
#   --installed-lean <ver>       override host Lean detection (testing / explicit)
#   --installed-coq  <ver>       override host Coq detection
#   --strict-version             promote version_drift from advisory (exit 0) to
#                                a hard error (exit 2)
#   --json-out <path>            also write the classified verdict JSON here
#   --artifact-root <dir>        override the run-bundle root (default artifacts/)
#
# Exit codes:
#   0  verified (or version_drift in advisory mode)
#   1  proof_regression (recheck failed — fail-closed; escalate to maintainers)
#   2  version_drift under --strict-version (toolchain must be updated)
#   3  CLI / environment error (bundle missing, docker unavailable in --via docker)
#
set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly COMPONENT="proof_bundle_operator_verify"
readonly BEAD_ID="bd-cixqu.25.4"
readonly OPERATOR_VERDICT_SCHEMA="franken-engine.proof-bundle-operator-verdict.v1"
# Single source of truth: the Y.2 checker + clean-room image. These strings are
# pinned to the Rust canonical constants (PROOF_BUNDLE_VERIFIER_IMAGE /
# PROOF_BUNDLE_VERIFIER_GATE in ga_exit_evidence_package.rs); the Y.4 gate
# asserts they agree (anti-drift pin).
readonly Y2_CHECKER="docker/y2_proof_bundle_verifier/verify_proof_bundle.py"
readonly Y2_IMAGE_TAG="frankenengine/y2-proof-bundle-verifier:bd-cixqu.25.2"
readonly Y2_BUILD_GATE="scripts/run_y2_proof_bundle_verifier.sh"
readonly EXPORT_TOOL="scripts/export_proof_bundle.sh"
readonly PROOF_SCHEMA="franken-engine.theorem-backed-compiler.proof.v1"
readonly ARTIFACT_ROOT_DEFAULT="${ROOT_DIR}/artifacts/${COMPONENT}"

usage() {
  cat >&2 <<EOF
usage: $0 verify <bundle.tar.gz|bundle-dir> [flags]
       $0 selftest
       $0 -h | --help

verify flags:
  --via docker|local|auto   checker path (default auto: docker for a tar when the
                            daemon is reachable, else local python3)
  --expected-lean <ver>     operator-expected Lean pin (mismatch => version_drift)
  --expected-coq  <ver>     operator-expected Coq pin
  --installed-lean <ver>    override host Lean detection
  --installed-coq  <ver>    override host Coq detection
  --strict-version          treat version_drift as a hard error (exit 2)
  --json-out <path>         also write the classified verdict JSON
  --artifact-root <dir>     override run-bundle root

exit: 0 verified/advisory-drift · 1 proof_regression · 2 strict drift · 3 CLI/env
EOF
}

die() {
  echo "[${COMPONENT}] ERROR: $*" >&2
  exit 3
}

# --- run-bundle plumbing (bd-cixqu.45) --------------------------------------
RUN_DIR=""
EVENTS_PATH=""
COMMANDS_PATH=""
TRACE_ID=""

init_run_bundle() {
  local artifact_root="$1"
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="${artifact_root}/${ts}"
  EVENTS_PATH="${RUN_DIR}/events.jsonl"
  COMMANDS_PATH="${RUN_DIR}/commands.txt"
  TRACE_ID="trace-${COMPONENT}-${ts}"
  mkdir -p "${RUN_DIR}"
  : >"${EVENTS_PATH}"
  : >"${COMMANDS_PATH}"
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

record_cmd() { printf '$ %s\n' "$*" >>"${COMMANDS_PATH}"; }

# Detect a host proof-assistant version, best-effort. Echoes a bare semver
# (e.g. 4.7.0) or empty. Args: <tool> <version-arg>.
detect_assistant_version() {
  local tool="$1" varg="$2"
  command -v "${tool}" >/dev/null 2>&1 || { printf '' ; return 0; }
  local out
  out="$("${tool}" "${varg}" 2>/dev/null || true)"
  # First semver-looking token.
  printf '%s' "${out}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

# Normalize a pin string to a bare semver. "leanprover/lean4:v4.7.0" -> 4.7.0,
# "coq-8.19.2" -> 8.19.2, "v4.6.0" -> 4.6.0. Echoes empty if none found.
normalize_pin() {
  printf '%s' "${1:-}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

# Run the Y.2 checker on a bundle via local python3. Args: <bundle> <verdict-out>.
# Echoes nothing; returns the checker exit code (0 pass / 1 fail / 2 env).
check_local() {
  local bundle="$1" verdict_out="$2"
  [[ -f "${ROOT_DIR}/${Y2_CHECKER}" ]] || die "Y.2 checker not found: ${Y2_CHECKER}"
  record_cmd "python3 ${Y2_CHECKER} verify-proof-bundle ${bundle}"
  local rc=0
  python3 "${ROOT_DIR}/${Y2_CHECKER}" verify-proof-bundle "${bundle}" \
    >"${verdict_out}" 2>>"${COMMANDS_PATH}" || rc=$?
  return "${rc}"
}

# Run the Y.2 checker on a bundle via the clean-room docker image.
# Args: <bundle.tar.gz> <verdict-out>. Returns the container exit code.
check_docker() {
  local bundle="$1" verdict_out="$2"
  command -v docker >/dev/null 2>&1 || die "docker not found on PATH (use --via local)"
  docker info >/dev/null 2>&1 || die "docker daemon not reachable (use --via local)"
  [[ "${bundle}" == *.tar.gz || "${bundle}" == *.tgz ]] \
    || die "docker path needs a bundle tar (.tar.gz); got ${bundle} (use --via local)"
  if ! docker image inspect "${Y2_IMAGE_TAG}" >/dev/null 2>&1; then
    log_event "image" "build" "building ${Y2_IMAGE_TAG} via ${Y2_BUILD_GATE}"
    record_cmd "bash ${Y2_BUILD_GATE} build"
    bash "${Y2_BUILD_GATE}" build >>"${COMMANDS_PATH}" 2>&1 \
      || die "Y.2 image build failed (use --via local)"
  fi
  local abs
  abs="$(cd "$(dirname "${bundle}")" && pwd)/$(basename "${bundle}")"
  record_cmd "docker run --rm --network=none -v ${abs}:/input/proof_bundle.tar.gz:ro ${Y2_IMAGE_TAG} verify-proof-bundle /input/proof_bundle.tar.gz"
  local rc=0
  docker run --rm --network=none \
    -v "${abs}:/input/proof_bundle.tar.gz:ro" \
    "${Y2_IMAGE_TAG}" verify-proof-bundle /input/proof_bundle.tar.gz \
    >"${verdict_out}" 2>>"${COMMANDS_PATH}" || rc=$?
  return "${rc}"
}

# Read proof_assistant_versions.json from a bundle (tar or dir). Echoes
# "<lean_pin>|<coq_pin>" (raw pin strings) or "|" if unavailable.
read_bundle_pins() {
  local bundle="$1"
  BPB_BUNDLE="${bundle}" python3 <<'PY'
import json, os, sys, tarfile, tempfile
bundle = os.environ["BPB_BUNDLE"]

def load_from_dir(root):
    for dirpath, _dirs, files in os.walk(root):
        if "proof_assistant_versions.json" in files:
            with open(os.path.join(dirpath, "proof_assistant_versions.json"), encoding="utf-8") as fh:
                return json.load(fh)
    return None

data = None
if os.path.isdir(bundle):
    data = load_from_dir(bundle)
elif os.path.isfile(bundle):
    tmp = tempfile.mkdtemp(prefix="y4-pins-")
    try:
        with tarfile.open(bundle, "r:*") as tar:
            # safe-ish: only extract the versions file
            for m in tar.getmembers():
                if m.name.endswith("proof_assistant_versions.json") and m.isfile():
                    fobj = tar.extractfile(m)
                    if fobj is not None:
                        data = json.load(fobj)
                        break
    except Exception:
        data = None
lean = (data or {}).get("lean4", "") if data else ""
coq = (data or {}).get("coq", "") if data else ""
sys.stdout.write(f"{lean}|{coq}")
PY
}

# --- classification core ------------------------------------------------------
classify_and_emit() {
  # classify_and_emit <verdict_out> <checker_rc> <via> <bundle> <expected_lean>
  #                    <expected_coq> <installed_lean> <installed_coq>
  #                    <pinned_lean> <pinned_coq> <classified_out>
  local verdict_out="$1" checker_rc="$2" via="$3" bundle="$4"
  local exp_lean="$5" exp_coq="$6" inst_lean="$7" inst_coq="$8"
  local pin_lean="$9" pin_coq="${10}" classified_out="${11}"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  Y4_VERDICT="${verdict_out}" Y4_RC="${checker_rc}" Y4_VIA="${via}" \
  Y4_SOURCE="$(basename "${bundle}")" Y4_SCHEMA="${OPERATOR_VERDICT_SCHEMA}" \
  Y4_BEAD="${BEAD_ID}" Y4_COMPONENT="${COMPONENT}" Y4_NOW="${now}" \
  Y4_EXP_LEAN="${exp_lean}" Y4_EXP_COQ="${exp_coq}" \
  Y4_INST_LEAN="${inst_lean}" Y4_INST_COQ="${inst_coq}" \
  Y4_PIN_LEAN="${pin_lean}" Y4_PIN_COQ="${pin_coq}" \
  python3 - "${classified_out}" <<'PY'
import json, os, sys

out_path = sys.argv[1]
try:
    with open(os.environ["Y4_VERDICT"], encoding="utf-8") as fh:
        recheck = json.load(fh)
except Exception as exc:  # noqa: BLE001 — fail closed if the checker emitted nothing
    recheck = {"verdict": "fail", "reasons": [f"checker produced no parseable verdict: {exc}"],
               "proofs": [], "claim_count": 0}

recheck_verdict = recheck.get("verdict", "fail")
checker_rc = os.environ["Y4_RC"]

# Per-assistant drift status. "expected_mismatch" (bundle built with an
# unexpected toolchain) > "drift" (operator toolchain != bundle pin) >
# "aligned" > "absent" (operator has no such toolchain — purely informational,
# the recheck digest is version-independent).
def assistant_status(pinned, installed, expected):
    if expected and pinned and expected != pinned:
        return "expected_mismatch"
    if installed and pinned and installed != pinned:
        return "drift"
    if installed and pinned and installed == pinned:
        return "aligned"
    return "absent"

pin_lean = os.environ["Y4_PIN_LEAN"]
pin_coq = os.environ["Y4_PIN_COQ"]
inst_lean = os.environ["Y4_INST_LEAN"]
inst_coq = os.environ["Y4_INST_COQ"]
exp_lean = os.environ["Y4_EXP_LEAN"]
exp_coq = os.environ["Y4_EXP_COQ"]

lean_status = assistant_status(pin_lean, inst_lean, exp_lean)
coq_status = assistant_status(pin_coq, inst_coq, exp_coq)
statuses = [lean_status, coq_status]

if "expected_mismatch" in statuses:
    version_status = "expected_mismatch"
elif "drift" in statuses:
    version_status = "drift"
elif "aligned" in statuses:
    version_status = "aligned"
else:
    version_status = "absent"

# Failing claims surfaced from the Y.2 verdict for operator triage.
failing = []
for p in recheck.get("proofs", []):
    bad = (p.get("integrity") not in (None, "intact")) or (p.get("proven") is False) \
        or (p.get("schema_ok") is False)
    if bad:
        failing.append(p.get("claim_id", p.get("file", "unknown")))

if recheck_verdict != "pass":
    classification = "proof_regression"
    action = ("ESCALATE to FrankenEngine maintainers: the bundle's recheck digest "
              "no longer reproduces the trust anchor (a proof body/verdict changed "
              "or the bundle is incomplete). Do NOT treat this release as verified. "
              "Attach this verdict JSON — failing_claims and recheck.reasons name the "
              "specific proof(s).")
elif version_status in ("drift", "expected_mismatch"):
    classification = "version_drift"
    action = ("UPDATE your local proof assistant to the bundle's pinned versions "
              "(proof_assistant_versions.json) before re-running the underlying "
              "Lean/Coq proofs. The recheck digest is version-independent and DID "
              "verify, so this is advisory — the release content is intact.")
else:
    classification = "verified"
    note = "" if version_status == "aligned" else \
        " (proof-assistant toolchain not installed locally; the recheck digest is " \
        "version-independent, so verification holds regardless)"
    action = (f"VERIFIED: the recheck digest matches the trust anchor; "
              f"{recheck.get('claim_count', 0)} proof(s) intact and proven{note}.")

classified = {
    "schema_version": os.environ["Y4_SCHEMA"],
    "component": os.environ["Y4_COMPONENT"],
    "bead_id": os.environ["Y4_BEAD"],
    "source": os.environ["Y4_SOURCE"],
    "via": os.environ["Y4_VIA"],
    "checker_exit_code": int(checker_rc) if checker_rc.lstrip("-").isdigit() else checker_rc,
    "recheck_verdict": recheck_verdict,
    "classification": classification,
    "recommended_action": action,
    "claim_count": recheck.get("claim_count", 0),
    "failing_claims": failing,
    "recomputed_recheck_digest": recheck.get("recomputed_recheck_digest"),
    "expected_recheck_digest": recheck.get("expected_recheck_digest"),
    "version_status": version_status,
    "version_detail": {
        "pinned_lean4": pin_lean or None,
        "pinned_coq": pin_coq or None,
        "installed_lean4": inst_lean or None,
        "installed_coq": inst_coq or None,
        "expected_lean4": exp_lean or None,
        "expected_coq": exp_coq or None,
        "lean_status": lean_status,
        "coq_status": coq_status,
    },
    "recheck": recheck,
    "generated_utc": os.environ["Y4_NOW"],
}
rendered = json.dumps(classified, indent=2, sort_keys=True)
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(rendered + "\n")
print(rendered)
# Stable exit signalling the classification back to the shell.
sys.exit({"verified": 0, "version_drift": 10, "proof_regression": 1}[classification])
PY
}

write_manifest() {
  local classification="$1"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RUN_DIR="${RUN_DIR}" COMPONENT_ENV="${COMPONENT}" BEAD="${BEAD_ID}" \
  TRACE_ID="${TRACE_ID}" CLASSIFICATION="${classification}" NOW="${now}" \
  python3 <<'PY'
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
    "schema_id": "franken-engine.proof-artifact-manifest.v1",
    "component": os.environ["COMPONENT_ENV"],
    "bead_id": os.environ["BEAD"],
    "scope": "Y.4 operator proof-bundle verification",
    "trace_id": os.environ["TRACE_ID"],
    "generated_utc": os.environ["NOW"],
    "classification": os.environ["CLASSIFICATION"],
    "operator_verification": {
        "rerun": "runbooks/scripts/verify_proof_bundle.sh verify <bundle.tar.gz>",
        "doc": "docs/PROOF_BUNDLE_VERIFICATION.md",
        "gate": "scripts/run_y4_proof_bundle_operator_surface.sh ci",
    },
    "artifact_content_hashes": artifacts,
}
with open(os.path.join(run_dir, "run_manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

run_verify() {
  local bundle="" via="auto" strict="0" json_out=""
  local exp_lean="" exp_coq="" inst_lean="__detect__" inst_coq="__detect__"
  local artifact_root="${ARTIFACT_ROOT_DEFAULT}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --via) via="${2:-}"; shift 2 ;;
      --expected-lean) exp_lean="$(normalize_pin "${2:-}")"; shift 2 ;;
      --expected-coq) exp_coq="$(normalize_pin "${2:-}")"; shift 2 ;;
      --installed-lean) inst_lean="$(normalize_pin "${2:-}")"; shift 2 ;;
      --installed-coq) inst_coq="$(normalize_pin "${2:-}")"; shift 2 ;;
      --strict-version) strict="1"; shift ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      --artifact-root) artifact_root="${2:-}"; shift 2 ;;
      -*) die "unknown flag: $1" ;;
      *) [[ -z "${bundle}" ]] && bundle="$1" || die "unexpected argument: $1"; shift ;;
    esac
  done
  [[ -n "${bundle}" ]] || { usage; exit 3; }
  [[ -e "${bundle}" ]] || die "bundle not found: ${bundle}"
  case "${via}" in docker|local|auto) ;; *) die "invalid --via: ${via}" ;; esac

  init_run_bundle "${artifact_root}"
  log_event "verify" "started" "bundle=$(basename "${bundle}") via=${via}"

  # Resolve the checker path. auto => docker for a tar + reachable daemon.
  local resolved="${via}"
  if [[ "${via}" == "auto" ]]; then
    if [[ ( "${bundle}" == *.tar.gz || "${bundle}" == *.tgz ) ]] \
        && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      resolved="docker"
    else
      resolved="local"
    fi
  fi
  log_event "path" "resolved" "checker via ${resolved}"

  # Resolve toolchain versions for drift detection.
  local pins pin_lean pin_coq
  pins="$(read_bundle_pins "${bundle}")"
  pin_lean="$(normalize_pin "${pins%%|*}")"
  pin_coq="$(normalize_pin "${pins##*|}")"
  [[ "${inst_lean}" == "__detect__" ]] && inst_lean="$(detect_assistant_version lean --version)"
  [[ "${inst_coq}" == "__detect__" ]] && inst_coq="$(detect_assistant_version coqc --version)"

  local verdict_out="${RUN_DIR}/recheck_verdict.json"
  local classified_out="${RUN_DIR}/operator_verdict.json"
  local checker_rc=0
  if [[ "${resolved}" == "docker" ]]; then
    check_docker "${bundle}" "${verdict_out}" || checker_rc=$?
  else
    check_local "${bundle}" "${verdict_out}" || checker_rc=$?
  fi
  log_event "recheck" "exit-${checker_rc}" "Y.2 checker via ${resolved}"

  local class_rc=0
  classify_and_emit "${verdict_out}" "${checker_rc}" "${resolved}" "${bundle}" \
    "${exp_lean}" "${exp_coq}" "${inst_lean}" "${inst_coq}" \
    "${pin_lean}" "${pin_coq}" "${classified_out}" >/dev/null || class_rc=$?

  local classification exit_code
  case "${class_rc}" in
    0) classification="verified"; exit_code=0 ;;
    10) classification="version_drift"; exit_code=$([[ "${strict}" == "1" ]] && echo 2 || echo 0) ;;
    1) classification="proof_regression"; exit_code=1 ;;
    *) classification="error"; exit_code=3 ;;
  esac

  [[ -n "${json_out}" ]] && cp "${classified_out}" "${json_out}"
  write_manifest "${classification}"
  log_event "verify" "${classification}" "exit ${exit_code}"

  # Operator-facing summary on stderr; machine verdict already in operator_verdict.json.
  local action
  action="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["recommended_action"])' "${classified_out}")"
  echo "[${COMPONENT}] classification : ${classification}" >&2
  echo "[${COMPONENT}] recheck verdict : $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["recheck_verdict"])' "${classified_out}")" >&2
  echo "[${COMPONENT}] version status  : $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version_status"])' "${classified_out}")" >&2
  echo "[${COMPONENT}] action          : ${action}" >&2
  echo "[${COMPONENT}] verdict json    : ${classified_out#"${ROOT_DIR}"/}" >&2
  echo "[${COMPONENT}] artifacts       : ${RUN_DIR#"${ROOT_DIR}"/}" >&2
  exit "${exit_code}"
}

# --- selftest: prove all three classifications without an engine build --------
write_fixture_source() {
  local dir="$1"
  mkdir -p "${dir}"
  FX_DIR="${dir}" FX_SCHEMA="${PROOF_SCHEMA}" python3 <<'PY'
import hashlib, json, os
d = os.environ["FX_DIR"]
schema = os.environ["FX_SCHEMA"]
for claim_id, track, kind in [
    ("FE-CLAIM-016", "G.2,G.3", "formal-spec-isomorphism"),
    ("FE-CLAIM-020", "G.7,G.8", "theorem-backed-compiler"),
]:
    proof = {
        "schema_version": schema, "claim_id": claim_id, "track": track,
        "proof_kind": kind, "verdict": "proven",
        "generated_utc": "2026-01-01T00:00:00Z", "source_module": "y4-selftest-fixture",
    }
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    proof["content_hash"] = "sha256:" + hashlib.sha256(enc).hexdigest()
    with open(os.path.join(d, claim_id + ".proof.json"), "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2, sort_keys=True)
        fh.write("\n")
PY
}

run_selftest() {
  local ts work
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  work="${ARTIFACT_ROOT_DEFAULT}/${ts}-selftest"
  mkdir -p "${work}"
  echo "[${COMPONENT}] selftest workdir: ${work#"${ROOT_DIR}"/}"

  local fx="${work}/fixture_proof_source"
  write_fixture_source "${fx}"
  bash "${EXPORT_TOOL}" export "${fx}" "${work}/export" >/dev/null \
    || { echo "[${COMPONENT}] SELFTEST FAIL: fixture export failed" >&2; return 1; }
  local valid="${work}/export/proof_bundle.tar.gz"
  [[ -f "${valid}" ]] || { echo "[${COMPONENT}] SELFTEST FAIL: no exported tar" >&2; return 1; }

  local fail=0

  # 1. valid bundle, aligned toolchain => verified, exit 0.
  local rc=0
  "$0" verify "${valid}" --via local --installed-lean 4.7.0 --installed-coq 8.19.2 \
    --json-out "${work}/v_verified.json" >/dev/null 2>&1 || rc=$?
  if [[ "${rc}" -eq 0 ]] && grep -q '"classification": "verified"' "${work}/v_verified.json"; then
    echo "[${COMPONENT}] selftest 1/4 verified (aligned)            : PASS"
  else
    echo "[${COMPONENT}] selftest 1/4 verified (aligned)            : FAIL (rc=${rc})" >&2; fail=1
  fi

  # 2. valid bundle, drifted toolchain => version_drift, advisory exit 0.
  #    Bundle pins v4.7.0, so the drift fixture uses a non-pin version (4.6.0).
  rc=0
  "$0" verify "${valid}" --via local --installed-lean 4.6.0 \
    --json-out "${work}/v_drift.json" >/dev/null 2>&1 || rc=$?
  if [[ "${rc}" -eq 0 ]] && grep -q '"classification": "version_drift"' "${work}/v_drift.json"; then
    echo "[${COMPONENT}] selftest 2/4 version_drift (advisory exit0) : PASS"
  else
    echo "[${COMPONENT}] selftest 2/4 version_drift (advisory exit0) : FAIL (rc=${rc})" >&2; fail=1
  fi

  # 3. valid bundle, drifted toolchain, --strict-version => exit 2.
  rc=0
  "$0" verify "${valid}" --via local --installed-lean 4.6.0 --strict-version \
    --json-out "${work}/v_strict.json" >/dev/null 2>&1 || rc=$?
  if [[ "${rc}" -eq 2 ]] && grep -q '"classification": "version_drift"' "${work}/v_strict.json"; then
    echo "[${COMPONENT}] selftest 3/4 version_drift (strict exit2)   : PASS"
  else
    echo "[${COMPONENT}] selftest 3/4 version_drift (strict exit2)   : FAIL (rc=${rc})" >&2; fail=1
  fi

  # 4. tampered bundle => proof_regression, exit 1 (fail-closed).
  local tstage="${work}/tamper"
  mkdir -p "${tstage}"
  tar -xzf "${valid}" -C "${tstage}"
  local victim
  victim="$(find "${tstage}" -name '*.proof.json' | sort | head -n1)"
  VICTIM="${victim}" python3 -c '
import json, os
p = os.environ["VICTIM"]
proof = json.load(open(p))
proof["source_module"] = "tampered-after-export"
json.dump(proof, open(p, "w"), indent=2, sort_keys=True)
open(p, "a").write("\n")
'
  local broot
  broot="$(cd "${tstage}" && find . -maxdepth 1 -mindepth 1 -type d | head -n1)"; broot="${broot#./}"
  ( cd "${tstage}" && tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
      --numeric-owner -czf "${work}/proof_bundle_tampered.tar.gz" "${broot}" )
  rc=0
  "$0" verify "${work}/proof_bundle_tampered.tar.gz" --via local --installed-lean 4.7.0 \
    --json-out "${work}/v_regression.json" >/dev/null 2>&1 || rc=$?
  if [[ "${rc}" -eq 1 ]] && grep -q '"classification": "proof_regression"' "${work}/v_regression.json"; then
    echo "[${COMPONENT}] selftest 4/4 proof_regression (exit1)       : PASS"
  else
    echo "[${COMPONENT}] selftest 4/4 proof_regression (exit1)       : FAIL (rc=${rc})" >&2; fail=1
  fi

  if [[ "${fail}" -eq 0 ]]; then
    echo "[${COMPONENT}] SELFTEST PASS: verified / version_drift / strict-drift / proof_regression all classified"
    return 0
  fi
  echo "[${COMPONENT}] SELFTEST FAIL" >&2
  return 1
}

main() {
  local mode="${1:-}"
  case "${mode}" in
    -h|--help) usage; exit 0 ;;
    verify) shift; run_verify "$@" ;;
    selftest) run_selftest; exit $? ;;
    "") usage; exit 3 ;;
    *) echo "unknown mode: ${mode}" >&2; usage; exit 3 ;;
  esac
}

main "$@"
