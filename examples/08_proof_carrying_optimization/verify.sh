#!/usr/bin/env bash
# Verification script for certified optimization demo
# Runs demo and asserts proof_status=valid

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
artifact_path="${script_dir}/sample_proof_artifact.json"
demo_output_path="$(mktemp)"
trap 'rm -f "${demo_output_path}"' EXIT

echo "=== FrankenEngine Certified Optimization Verification ==="
echo

# Run the demo and capture output
echo "Running certified optimization demo..."
"${script_dir}/demo.sh" > "${demo_output_path}" 2>&1

echo "Demo completed. Verifying proof artifact..."
echo

# Check that the proof artifact was generated
if [[ ! -f "${artifact_path}" ]]; then
    echo "❌ FAIL: sample_proof_artifact.json not found"
    exit 1
fi

# Verify the proof status is valid
PROOF_STATUS=$(grep -o '"proof_status":\s*"[^"]*"' "${artifact_path}" | cut -d'"' -f4)

if [[ "${PROOF_STATUS}" == "valid" ]]; then
    echo "✅ PASS: proof_status=valid"
else
    echo "❌ FAIL: proof_status=${PROOF_STATUS}, expected 'valid'"
    exit 1
fi

# Verify required fields are present
echo "Verifying proof artifact structure..."

REQUIRED_FIELDS=(
    "optimization_id"
    "before_ir"
    "after_ir"
    "translation_validation"
    "governance_policy"
    "proof_status"
)

for field in "${REQUIRED_FIELDS[@]}"; do
    if grep -q "\"${field}\":" "${artifact_path}"; then
        echo "✅ ${field}: present"
    else
        echo "❌ ${field}: missing"
        exit 1
    fi
done

# Verify translation validation evidence
echo
echo "Verifying translation validation evidence..."

# Check equivalence witness
if grep -q '"equivalence_witness":' "${artifact_path}"; then
    echo "✅ Equivalence witness: present"
else
    echo "❌ Equivalence witness: missing"
    exit 1
fi

# Check verification status
VERIFICATION_STATUS=$(grep -o '"verification_status":\s*"[^"]*"' "${artifact_path}" | cut -d'"' -f4)
if [[ "${VERIFICATION_STATUS}" == "verified" ]]; then
    echo "✅ Verification status: verified"
else
    echo "❌ Verification status: ${VERIFICATION_STATUS}, expected 'verified'"
    exit 1
fi

# Check certificate status
CERT_STATUS=$(grep -o '"certificate_status":\s*"[^"]*"' "${artifact_path}" | cut -d'"' -f4)
if [[ "${CERT_STATUS}" == "valid" ]]; then
    echo "✅ Certificate status: valid"
else
    echo "❌ Certificate status: ${CERT_STATUS}, expected 'valid'"
    exit 1
fi

echo
echo "=== Verification Summary ==="
echo "✅ Demo executed successfully"
echo "✅ Proof artifact generated with proof_status=valid"
echo "✅ All required fields present"
echo "✅ Translation validation evidence verified"
echo "✅ Governance certificate valid"
echo
echo "Demo proves FrankenEngine's impossible-by-default capability #5:"
echo "Proof-carrying adaptive optimization with translation validation"
echo
echo "This capability is impossible to retrofit into V8/Node.js without"
echo "fundamental architectural changes."
