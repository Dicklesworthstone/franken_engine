#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
receipt_path="$(mktemp)"
trap 'rm -f "${receipt_path}"' EXIT

cd "${repo_root}"
cargo run --bin franken-decision-demo > "${receipt_path}"

jq -e '
  . as $receipt
  | (["allow", "challenge", "sandbox", "suspend", "terminate", "quarantine"] | index($receipt.decision) != null)
  and ($receipt.signature_hex | test("^[0-9a-f]{64}$"))
  and ($receipt.posterior_after_millionths | type == "number" and . >= 0 and . <= 1000000)
' "${receipt_path}" > /dev/null

cat "${receipt_path}"
