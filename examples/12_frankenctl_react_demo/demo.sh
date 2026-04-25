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

echo "frankenctl react compile exited with expected fail-closed status 25"
echo "captured report: ${report_path}"
cat "${report_path}"
