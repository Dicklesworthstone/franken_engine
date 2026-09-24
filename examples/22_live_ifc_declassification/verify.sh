#!/usr/bin/env bash
set -euo pipefail

# Live IFC/declassification example (bd-dpfvh; evidence rules bd-9vouw.20).
#
# Runs examples/live_ifc_declassification_example.rs, which drives the real
# FlowPolicy flow check and DeclassificationPipeline, publishes every receipt
# the pipeline signs (Ed25519) together with the run's verification key, and
# re-verifies the written artifacts from disk before it reports success. This
# script fails when the example fails, when the example's verdict line is
# missing, or when the artifacts visible locally do not show an approved flow
# under a verifiable signed receipt and a denied flow. It writes no evidence of
# its own.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
RCH_BIN="${RCH_BIN:-rch}"
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
target_dir="${CARGO_TARGET_DIR:-${IFC_DECLASSIFICATION_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_ifc_declassification_$(date +%s)_$$}}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="${repo_root}/artifacts/live_ifc_declassification_example/${timestamp}"
live_artifacts_dir="${artifact_dir}/live"

mkdir -p "${artifact_dir}" "${live_artifacts_dir}"
cd "${repo_root}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "Live IFC/declassification example"
echo "================================="
echo "Artifact directory: ${artifact_dir}"
echo ""

ifc_stdout="${artifact_dir}/live_ifc_stdout.log"
ifc_stderr="${artifact_dir}/live_ifc_stderr.log"

if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
    echo "Required rch binary not found: ${RCH_BIN}" >&2
    exit 2
fi

example_cmd=(
    "${RCH_BIN}" exec -- env
    "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}"
    "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}"
    "CARGO_TARGET_DIR=${target_dir}"
    "IFC_DECLASSIFICATION_OUTPUT_DIR=${live_artifacts_dir}"
    cargo run -p frankenengine-engine --example live_ifc_declassification_example --no-default-features
)

echo "Running: ${example_cmd[*]}"
set +e
"${example_cmd[@]}" > "${ifc_stdout}" 2> "${ifc_stderr}"
ifc_exit_code=$?
set -e

{
    echo "command: ${example_cmd[*]}"
    echo "exit_code: ${ifc_exit_code}"
} > "${artifact_dir}/command_transcript.log"

if grep -Eiq 'falling back to local|local fallback|running locally|\[RCH\] local \(|Dependency preflight blocked remote execution|RCH-E326' "${ifc_stdout}" "${ifc_stderr}"; then
    cat "${ifc_stderr}" >&2
    echo "rch reported local fallback; refusing local execution" >&2
    exit 125
fi

if [[ ${ifc_exit_code} -ne 0 ]]; then
    tail -n 40 "${ifc_stderr}" >&2
    echo "FAIL: live IFC example exited ${ifc_exit_code}" >&2
    exit "${ifc_exit_code}"
fi

# 1. The example's own disk re-verification verdict (printed only when every
#    receipt verified and both an approved and a denied flow were observed).
verdict_json="$(sed -n 's/^IFC_DEMO_VERDICT //p' "${ifc_stdout}" | tail -n 1)"
[[ -n "${verdict_json}" ]] || fail "example printed no IFC_DEMO_VERDICT line"
jq -e '
  .approved_with_verified_receipt >= 1
  and .denied_without_flow >= 1
  and (.verification_key_hex | test("^[0-9a-f]{64}$"))
' <<<"${verdict_json}" > /dev/null || fail "verdict does not show an approved and a denied flow: ${verdict_json}"
echo "✓ Example re-verified its artifacts: ${verdict_json}"

# 2. When the artifacts are visible here (they stay on the worker when rch runs
#    the example remotely), check them directly as well.
report="${live_artifacts_dir}/report.json"
receipts="${live_artifacts_dir}/declassification_receipts.json"
key_file="${live_artifacts_dir}/verification_key.json"
if [[ -f "${report}" && -f "${receipts}" && -f "${key_file}" ]]; then
    jq -e '
      ([.scenarios[] | select(.declassification_approved)] | length) >= 1
      and ([.scenarios[] | select(.declassification_approved | not)] | length) >= 1
      and all(.scenarios[] | select(.declassification_approved);
              .flow_completed and .receipt_generated
              and (.receipt_hash | type == "string" and test("^[0-9a-f]{64}$")))
      and all(.scenarios[] | select(.declassification_approved | not); .flow_completed | not)
    ' "${report}" > /dev/null || fail "report.json does not show an approved flow with a receipt and a denied flow"
    echo "✓ report.json: approved flow carries a receipt hash; denied flow did not complete"

    # Independent Ed25519 check (PyNaCl, not the engine's verifier) of each
    # published signature over its published preimage; the example has
    # already bound each preimage to its receipt's fields.
    if python3 -c 'import nacl.signing' > /dev/null 2>&1; then
        python3 - "${receipts}" "${key_file}" <<'PY' || fail "independent Ed25519 check rejected a receipt"
import json
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

with open(sys.argv[1]) as handle:
    receipts = json.load(handle)
with open(sys.argv[2]) as handle:
    key = VerifyKey(bytes.fromhex(json.load(handle)["verification_key_hex"]))
if not receipts:
    sys.exit("no receipts were published")
for published in receipts:
    try:
        key.verify(bytes.fromhex(published["preimage_hex"]), bytes.fromhex(published["signature_hex"]))
    except BadSignatureError:
        sys.exit(f"{published['scenario_id']}: signature rejected")
print(f"✓ PyNaCl verified {len(receipts)} receipt signature(s) under the run's key")
PY
    else
        echo "SKIP: PyNaCl is not installed; the independent Ed25519 cross-check did not run"
    fi
else
    echo "NOTE: ${live_artifacts_dir} is not populated locally (remote run); only the example's own verdict was checked"
fi

echo ""
echo "✅ Live IFC/declassification example verified"
echo "📁 ${artifact_dir}"
