#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
input_path="examples/12_frankenctl_react_demo/sample.tsx"
work_dir="$(mktemp -d)"
report_path="${work_dir}/react_compile_report.json"
trap 'rm -rf "${work_dir}"' EXIT

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target_react_demo}"

cd "${repo_root}"

set +e
cargo run --quiet --bin frankenctl -- react compile \
  --input "${input_path}" \
  --source-form tsx \
  --runtime automatic \
  --trace-id "trace-react-demo" \
  --decision-id "decision-react-demo" \
  --policy-id "policy-react-demo" \
  --out "${report_path}" \
  >/dev/null
status=$?
set -e

if [[ "${status}" -ne 25 ]]; then
  echo "expected frankenctl react compile to fail closed with exit code 25, got ${status}" >&2
  exit 1
fi

jq -e '
  .schema_version == "franken-engine.frankenctl.react-cli-report.v1" and
  .command == "react-compile" and
  .support_status == "deferred" and
  .shipped == false and
  .blocked == true and
  .capability_id == "tsx-automatic-runtime-compile" and
  .request.input_path == "examples/12_frankenctl_react_demo/sample.tsx" and
  .request.source_form == "tsx" and
  .request.runtime_mode == "automatic" and
  .request.build_target == null and
  .diagnostic.error_code == "FE-RGC-016A-CAP-0005" and
  .diagnostic.fallback_mode == "reject_with_guidance" and
  .diagnostic.owning_implementation_bead == "bd-1lsy.3.6.2" and
  .diagnostic.parity_gate_bead == "bd-1lsy.9.7.1" and
  .diagnostic.product_surface_bead == "bd-1lsy.10.12.1" and
  .diagnostic.verification_lane == "react_compile_contract"
' "${report_path}" >/dev/null

echo "verified react compile contract report:"
jq '{support_status, blocked, capability_id, error_code: .diagnostic.error_code}' "${report_path}"
